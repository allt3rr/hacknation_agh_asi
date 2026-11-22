//! Weryfikacja aktywna podatności: nuclei uruchamiane jako proces (argumenty jako lista,
//! bez powłoki), tylko nieinwazyjne szablony CVE, bez serwerów OOB, cele wyłącznie z obserwacji
//! przebiegu po kontroli zakresu.

use crate::scope::Scope;
use anyhow::{bail, Context, Result};
use asi_core::model::Observation;
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

/// Tagi szablonów, których nigdy nie uruchamiamy.
pub const EXCLUDED_TAGS: &str = "dos,fuzz,intrusive,bruteforce,oast";

#[derive(Debug, Clone)]
pub struct NucleiOptions {
    pub binary: String,
    pub rate_limit: u32,
}

impl NucleiOptions {
    pub fn build_args(&self) -> Vec<String> {
        let mut a: Vec<String> = [
            "-silent",
            "-jsonl",
            "-no-color",
            "-duc", // bez aktualizacji w czasie działania
            "-ni",  // bez interactsh (OOB)
            "-tags",
            "cve",
            "-etags",
            EXCLUDED_TAGS,
            "-pt",
            "http,tcp,ssl",
            "-retries",
            "0",
            "-timeout",
            "10",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        a.extend(["-rl".into(), self.rate_limit.to_string()]);
        a
    }
}

/// Usługa potwierdzona szablonem CVE.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hit {
    pub ip: String,
    pub port: u16,
    pub cve_id: String,
}

/// Cele dla nuclei: otwarte usługi przebiegu w zakresie. HTTP jako origin URL, reszta jako `ip:port`.
pub fn select_targets(observations: &[Observation], scope: &Scope) -> Vec<String> {
    let mut out = BTreeSet::new();
    for o in observations.iter().filter(|o| o.state == "open") {
        let Ok(ip) = o.ip.parse::<IpAddr>() else {
            continue;
        };
        if !scope.allows_service(ip, o.port) {
            continue;
        }
        let host = match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        let scheme = o
            .http
            .as_ref()
            .and_then(|h| url::Url::parse(&h.url).ok())
            .map(|u| u.scheme().to_string());
        out.insert(match scheme {
            Some(s) => format!("{s}://{host}:{}", o.port),
            None => format!("{host}:{}", o.port),
        });
    }
    out.into_iter().collect()
}

fn cve_ids(item: &Value) -> Vec<String> {
    let mut ids: Vec<String> = match &item["info"]["classification"]["cve-id"] {
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    };
    if ids.is_empty() {
        if let Some(t) = item["template-id"].as_str() {
            if t.to_ascii_uppercase().starts_with("CVE-") {
                ids.push(t.to_string());
            }
        }
    }
    ids.into_iter().map(|s| s.to_ascii_uppercase()).collect()
}

/// `ip:port` z `host`/`matched-at` (URL albo `host:port`); `ip` z pola `ip`, gdy jest.
fn endpoint(item: &Value) -> Option<(String, u16)> {
    let raw = item["matched-at"]
        .as_str()
        .or(item["host"].as_str())?
        .to_string();
    let with_scheme = if raw.contains("://") {
        raw
    } else {
        format!("tcp://{raw}")
    };
    let url = url::Url::parse(&with_scheme).ok()?;
    let port = url.port_or_known_default()?;
    let ip = match item["ip"].as_str() {
        Some(ip) if !ip.is_empty() => ip.to_string(),
        _ => url.host_str()?.trim_matches(['[', ']']).to_string(),
    };
    ip.parse::<IpAddr>().ok()?;
    Some((ip, port))
}

/// Wynik JSONL nuclei → potwierdzone CVE na usługach. Linie, których nie da się odczytać, są pomijane.
pub fn parse_jsonl(out: &str) -> Vec<Hit> {
    let mut hits = BTreeSet::new();
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(item) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some((ip, port)) = endpoint(&item) else {
            continue;
        };
        for cve_id in cve_ids(&item) {
            hits.insert(Hit {
                ip: ip.clone(),
                port,
                cve_id,
            });
        }
    }
    hits.into_iter().collect()
}

/// Uruchamia nuclei na celach (stdin). `kill_on_drop`: anulowanie zabija proces.
pub async fn run(
    opts: &NucleiOptions,
    targets: &[String],
    token: &CancellationToken,
) -> Result<Vec<Hit>> {
    if targets.is_empty() {
        return Ok(vec![]);
    }
    let mut child = Command::new(&opts.binary)
        .args(opts.build_args())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("Nie można uruchomić {}", opts.binary))?;
    let mut stdin = child.stdin.take().context("brak stdin nuclei")?;
    stdin.write_all(targets.join("\n").as_bytes()).await?;
    drop(stdin);
    let out = tokio::select! {
        out = child.wait_with_output() => out?,
        _ = token.cancelled() => bail!("weryfikacja przerwana"),
    };
    if !out.status.success() {
        bail!(
            "nuclei zakończyło się kodem {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let allowed: HashSet<(String, u16)> = targets
        .iter()
        .filter_map(|t| endpoint(&serde_json::json!({ "host": t })))
        .collect();
    // odrzuć trafienia spoza listy celów (np. po przekierowaniu)
    Ok(parse_jsonl(&String::from_utf8_lossy(&out.stdout))
        .into_iter()
        .filter(|h| allowed.contains(&(h.ip.clone(), h.port)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::PortSet;
    use asi_core::model::HttpInfo;
    use asi_core::targets::classify;

    #[test]
    fn arguments_exclude_harmful_templates() {
        let args = NucleiOptions {
            binary: "nuclei".into(),
            rate_limit: 7,
        }
        .build_args();
        assert!(args.windows(2).any(|w| w == ["-rl", "7"]));
        assert!(args.windows(2).any(|w| w == ["-tags", "cve"]));
        assert!(args.windows(2).any(|w| w == ["-etags", EXCLUDED_TAGS]));
        assert!(args.contains(&"-ni".to_string()));
        for forbidden in ["-code", "-headless", "-fuzz", "-dast"] {
            assert!(!args.contains(&forbidden.to_string()), "{forbidden}");
        }
    }

    #[test]
    fn targets_respect_scope() {
        let targets = vec![classify("10.0.0.0/24").unwrap()];
        let mut scope = Scope::new(&targets, Some(PortSet::parse("80").unwrap()));
        scope.add_open_port("10.0.0.5".parse().unwrap(), 3306);
        let mut web = Observation::new("10.0.0.5".into(), 80, "tcp".into());
        web.http = Some(HttpInfo {
            url: "http://10.0.0.5:80/".into(),
            ..Default::default()
        });
        let db = Observation::new("10.0.0.5".into(), 3306, "tcp".into());
        let blocked_port = Observation::new("10.0.0.5".into(), 22, "tcp".into());
        let outside = Observation::new("192.168.1.1".into(), 80, "tcp".into());
        let got = select_targets(&[web, db, blocked_port, outside], &scope);
        assert_eq!(got, vec!["10.0.0.5:3306", "http://10.0.0.5:80"]);
    }

    #[test]
    fn parses_jsonl_hits() {
        let out = r#"{"template-id":"CVE-2021-41773","info":{"classification":{"cve-id":["cve-2021-41773"]}},"host":"http://172.30.100.11:80","matched-at":"http://172.30.100.11:80/cgi-bin/.%2e/etc/passwd","ip":"172.30.100.11"}
nie-json
{"template-id":"mysql-detect","info":{},"host":"172.30.100.14:3306"}
{"template-id":"CVE-2020-1938","info":{},"matched-at":"172.30.100.12:8009"}"#;
        assert_eq!(
            parse_jsonl(out),
            vec![
                Hit {
                    ip: "172.30.100.11".into(),
                    port: 80,
                    cve_id: "CVE-2021-41773".into()
                },
                Hit {
                    ip: "172.30.100.12".into(),
                    port: 8009,
                    cve_id: "CVE-2020-1938".into()
                },
            ]
        );
    }

    #[tokio::test]
    async fn missing_binary_is_an_error() {
        let opts = NucleiOptions {
            binary: "nuclei-nie-istnieje".into(),
            rate_limit: 1,
        };
        let token = CancellationToken::new();
        assert!(run(&opts, &["10.0.0.1:80".into()], &token).await.is_err());
        assert!(run(&opts, &[], &token).await.unwrap().is_empty());
    }
}

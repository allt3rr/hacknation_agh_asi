//! Weryfikacja aktywna podatności: nuclei uruchamiane jako proces (argumenty jako lista,
//! bez powłoki), tylko nieinwazyjne szablony CVE, bez serwerów OOB, cele wyłącznie z obserwacji
//! przebiegu po kontroli zakresu.

use crate::scope::Scope;
use anyhow::{bail, Context, Result};
use asi_core::model::Observation;
use asi_core::vuln::severity_from_cvss;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Tagi szablonów, których nigdy nie uruchamiamy: obciążające lub zmieniające stan celu
/// (wykonanie kodu, wstrzyknięcia SQL, wgrywanie plików, próby logowania, połączenia zwrotne).
pub const EXCLUDED_TAGS: &str =
    "dos,fuzz,intrusive,bruteforce,oast,rce,sqli,file-upload,default-login";

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

/// Usługa potwierdzona szablonem CVE, z oceną z szablonu (gdy CVE nie ma w wyniku NVD).
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub ip: String,
    pub port: u16,
    pub cve_id: String,
    pub name: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub description: String,
}

/// Severity: z CVSS szablonu, a bez niego z pola `severity` szablonu.
fn severity(info: &Value, score: Option<f64>) -> String {
    if score.is_some() {
        return severity_from_cvss(score).into();
    }
    match info["severity"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "critical" => "Critical",
        "high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Info",
    }
    .into()
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
    let mut hits = BTreeMap::new();
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(item) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some((ip, port)) = endpoint(&item) else {
            continue;
        };
        let info = &item["info"];
        let class = &info["classification"];
        let score = class["cvss-score"].as_f64();
        for cve_id in cve_ids(&item) {
            hits.entry((ip.clone(), port, cve_id.clone()))
                .or_insert_with(|| Hit {
                    ip: ip.clone(),
                    port,
                    cve_id,
                    name: info["name"].as_str().unwrap_or("").to_string(),
                    severity: severity(info, score),
                    cvss_score: score,
                    cvss_vector: class["cvss-metrics"].as_str().map(String::from),
                    description: info["description"]
                        .as_str()
                        .unwrap_or("")
                        .trim()
                        .to_string(),
                });
        }
    }
    hits.into_values().collect()
}

/// Wynik weryfikacji. `interrupted`: przerwana terminem (koniec okna) albo anulowaniem —
/// `hits` zawiera trafienia zgłoszone do tej chwili.
#[derive(Debug, Default)]
pub struct Outcome {
    pub hits: Vec<Hit>,
    pub interrupted: bool,
}

async fn until(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Uruchamia nuclei na celach (stdin). Wynik czytany na bieżąco, więc termin lub anulowanie
/// zabija proces (`kill_on_drop`), ale zachowuje dotychczasowe trafienia.
pub async fn run(
    opts: &NucleiOptions,
    targets: &[String],
    token: &CancellationToken,
    deadline: Option<Instant>,
) -> Result<Outcome> {
    if targets.is_empty() {
        return Ok(Outcome::default());
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
    let mut stderr = child.stderr.take().context("brak stderr nuclei")?;
    let errors = tokio::spawn(async move {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s).await;
        s
    });
    let mut lines = BufReader::new(child.stdout.take().context("brak stdout nuclei")?).lines();
    let mut out = String::new();
    let mut interrupted = false;
    loop {
        tokio::select! {
            line = lines.next_line() => match line? {
                Some(l) => {
                    out.push_str(&l);
                    out.push('\n');
                }
                None => break,
            },
            _ = token.cancelled() => { interrupted = true; break }
            _ = until(deadline) => { interrupted = true; break }
        }
    }
    if interrupted {
        let _ = child.kill().await;
    } else {
        let status = child.wait().await?;
        if !status.success() {
            bail!(
                "nuclei zakończyło się kodem {:?}: {}",
                status.code(),
                errors.await.unwrap_or_default().trim()
            );
        }
    }
    let allowed: HashSet<(String, u16)> = targets
        .iter()
        .filter_map(|t| endpoint(&serde_json::json!({ "host": t })))
        .collect();
    // odrzuć trafienia spoza listy celów (np. po przekierowaniu)
    let hits = parse_jsonl(&out)
        .into_iter()
        .filter(|h| allowed.contains(&(h.ip.clone(), h.port)))
        .collect();
    Ok(Outcome { hits, interrupted })
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
        let out = r#"{"template-id":"CVE-2021-41773","info":{"name":"Apache 2.4.49 - Path Traversal","severity":"high","description":" Path traversal. ","classification":{"cve-id":["cve-2021-41773"],"cvss-score":7.5,"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},"host":"http://172.30.100.11:80","matched-at":"http://172.30.100.11:80/cgi-bin/.%2e/etc/passwd","ip":"172.30.100.11"}
nie-json
{"template-id":"mysql-detect","info":{},"host":"172.30.100.14:3306"}
{"template-id":"CVE-2021-41773","info":{"classification":{"cve-id":"CVE-2021-41773"}},"matched-at":"http://172.30.100.11:80/icons/.%2e/x"}
{"template-id":"CVE-2020-1938","info":{"severity":"critical"},"matched-at":"172.30.100.12:8009"}"#;
        let hits = parse_jsonl(out);
        assert_eq!(hits.len(), 2, "duplikat tej samej usługi i CVE scalony");
        assert_eq!((hits[0].ip.as_str(), hits[0].port), ("172.30.100.11", 80));
        assert_eq!(hits[0].cve_id, "CVE-2021-41773");
        assert_eq!(hits[0].severity, "High");
        assert_eq!(hits[0].cvss_score, Some(7.5));
        assert_eq!(hits[0].description, "Path traversal.");
        assert_eq!(hits[0].name, "Apache 2.4.49 - Path Traversal");
        assert_eq!(
            (hits[1].cve_id.as_str(), hits[1].port),
            ("CVE-2020-1938", 8009)
        );
        assert_eq!(hits[1].severity, "Critical", "bez CVSS: severity szablonu");
        assert_eq!(hits[1].cvss_score, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deadline_keeps_hits_reported_so_far() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("asi-nuclei-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fake-nuclei");
        std::fs::write(
            &bin,
            "#!/bin/sh\ncat >/dev/null\necho '{\"template-id\":\"CVE-2021-41773\",\"info\":{},\"matched-at\":\"http://10.0.0.1:80/\"}'\nsleep 30\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let opts = NucleiOptions {
            binary: bin.to_string_lossy().into(),
            rate_limit: 1,
        };
        let started = std::time::Instant::now();
        let out = run(
            &opts,
            &["http://10.0.0.1:80".into()],
            &CancellationToken::new(),
            Some(Instant::now() + Duration::from_millis(500)),
        )
        .await
        .unwrap();
        assert!(out.interrupted);
        assert_eq!(out.hits.len(), 1, "trafienie sprzed terminu zachowane");
        assert!(started.elapsed() < Duration::from_secs(5), "proces zabity");
    }

    #[tokio::test]
    async fn missing_binary_is_an_error() {
        let opts = NucleiOptions {
            binary: "nuclei-nie-istnieje".into(),
            rate_limit: 1,
        };
        let token = CancellationToken::new();
        assert!(run(&opts, &["10.0.0.1:80".into()], &token, None)
            .await
            .is_err());
        assert!(run(&opts, &[], &token, None).await.unwrap().hits.is_empty());
    }
}

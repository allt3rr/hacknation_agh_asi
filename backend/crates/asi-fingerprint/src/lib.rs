//! Silnik sygnatur detekcyjnych (YAML). Tylko bezpieczna, pasywna detekcja:
//! nagłówki, ciasteczka, fragmenty HTML, tytuł, hash favicony, ścieżki GET bez logowania,
//! bannery usług z nmap, nazwa hosta.

use anyhow::{bail, Context, Result};
use asi_core::model::{Detection, Observation};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub category: String,
    #[serde(default = "d_confidence")]
    pub confidence: u8,
    #[serde(default, rename = "match")]
    pub mode: MatchMode,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub version: Option<VersionRule>,
}

fn d_confidence() -> u8 {
    70
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    /// wystarczy jedna reguła (pewność rośnie z liczbą spełnionych reguł)
    #[default]
    Any,
    /// wszystkie reguły muszą być spełnione
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Rule {
    /// nagłówek obecny (opcjonalnie wartość pasuje do regex)
    Header {
        name: String,
        #[serde(default)]
        regex: Option<String>,
    },
    /// nazwa ciasteczka; `prefix*` dopasowuje po prefiksie
    Cookie {
        name: String,
    },
    Body {
        regex: String,
    },
    Title {
        regex: String,
    },
    /// dodatkowa ścieżka pobierana GET-em (bez prób logowania)
    Path {
        path: String,
        #[serde(default)]
        status: Vec<u16>,
        #[serde(default)]
        body_regex: Option<String>,
    },
    /// sha256 pliku /favicon.ico (TODO: mmh3 zgodny z Shodan)
    FaviconSha256 {
        hash: String,
    },
    /// "service product version" z nmap
    Service {
        regex: String,
    },
    Hostname {
        regex: String,
    },
    Port {
        port: u16,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRule {
    pub source: VersionSource,
    #[serde(default)]
    pub header: Option<String>,
    /// pierwsza grupa przechwytująca = wersja
    pub regex: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionSource {
    Body,
    Header,
    Title,
    Service,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    Many(Vec<Signature>),
    One(Signature),
}

/// Ścieżka reguły `path` musi zostać w originie sondowanej usługi: pojedynczy `/` na początku,
/// bez schematu, `//`, `\`, `@` i znaków sterujących.
pub fn validate_path(path: &str) -> Result<()> {
    let ok = path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains("://")
        && !path.contains('\\')
        && !path.contains('@')
        && !path.chars().any(|c| c.is_control() || c.is_whitespace());
    if !ok {
        bail!("ścieżka {path:?} wychodzi poza origin usługi (dozwolona tylko ścieżka względna, np. /admin)");
    }
    Ok(())
}

impl Signature {
    /// Odrzuca sygnaturę z regułą `path` wychodzącą poza origin.
    pub fn validate(&self) -> Result<()> {
        for r in &self.rules {
            if let Rule::Path { path, .. } = r {
                validate_path(path).with_context(|| format!("sygnatura '{}'", self.id))?;
            }
        }
        Ok(())
    }

    fn patterns(&self) -> Vec<&str> {
        let mut v = Vec::new();
        for r in &self.rules {
            match r {
                Rule::Header { regex: Some(p), .. } => v.push(p.as_str()),
                Rule::Body { regex }
                | Rule::Title { regex }
                | Rule::Service { regex }
                | Rule::Hostname { regex } => v.push(regex.as_str()),
                Rule::Path {
                    body_regex: Some(p),
                    ..
                } => v.push(p.as_str()),
                _ => {}
            }
        }
        if let Some(ver) = &self.version {
            v.push(ver.regex.as_str());
        }
        v
    }
}

#[derive(Clone, Default)]
pub struct SignatureSet {
    sigs: Vec<Signature>,
    regex: HashMap<String, Regex>,
}

impl SignatureSet {
    /// Kompiluje sygnatury. Późniejsza sygnatura o tym samym `id` nadpisuje wcześniejszą
    /// (własne sygnatury użytkownika nadpisują wbudowane).
    pub fn new(input: Vec<Signature>) -> Result<Self> {
        let mut sigs: Vec<Signature> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for s in input {
            s.validate()?;
            match index.get(&s.id) {
                Some(&i) => sigs[i] = s,
                None => {
                    index.insert(s.id.clone(), sigs.len());
                    sigs.push(s);
                }
            }
        }
        let mut regex = HashMap::new();
        for s in &sigs {
            for p in s.patterns() {
                if regex.contains_key(p) {
                    continue;
                }
                let re = RegexBuilder::new(p)
                    .case_insensitive(true)
                    .size_limit(1 << 20)
                    .build()
                    .with_context(|| format!("sygnatura '{}': niepoprawny regex {p:?}", s.id))?;
                regex.insert(p.to_string(), re);
            }
        }
        Ok(Self { sigs, regex })
    }

    pub fn parse_yaml(text: &str) -> Result<Vec<Signature>> {
        let parsed: OneOrMany =
            serde_saphyr::from_str(text).context("YAML sygnatury: niepoprawny format")?;
        Ok(match parsed {
            OneOrMany::Many(v) => v,
            OneOrMany::One(s) => vec![s],
        })
    }

    pub fn load_dir(dir: &Path) -> Result<Vec<Signature>> {
        let mut out = Vec::new();
        if !dir.exists() {
            tracing::warn!("Brak katalogu sygnatur {}", dir.display());
            return Ok(out);
        }
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml")))
            .collect();
        paths.sort();
        for p in paths {
            let text = std::fs::read_to_string(&p)?;
            out.extend(Self::parse_yaml(&text).with_context(|| p.display().to_string())?);
        }
        Ok(out)
    }

    /// Wbudowane sygnatury + zapisane w bazie (YAML). Zapisane z niepoprawną ścieżką lub regexem
    /// są pomijane z ostrzeżeniem, żeby stara, niebezpieczna sygnatura nie trafiła do skanera.
    pub fn with_stored(builtin: Vec<Signature>, stored: &[(String, String)]) -> Result<Self> {
        let mut all = builtin;
        for (name, yaml) in stored {
            let parsed = Self::parse_yaml(yaml).and_then(|sigs| {
                Self::new(sigs.clone())?;
                Ok(sigs)
            });
            match parsed {
                Ok(sigs) => all.extend(sigs),
                Err(e) => tracing::warn!(%name, error = %e, "pominięto zapisaną sygnaturę"),
            }
        }
        Self::new(all)
    }

    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.sigs
    }

    /// Ścieżki, które moduł HTTP musi dodatkowo pobrać.
    pub fn required_paths(&self) -> Vec<String> {
        let mut set = BTreeSet::new();
        for s in &self.sigs {
            for r in &s.rules {
                match r {
                    Rule::Path { path, .. } => {
                        set.insert(path.clone());
                    }
                    Rule::FaviconSha256 { .. } => {
                        set.insert("/favicon.ico".to_string());
                    }
                    _ => {}
                }
            }
        }
        set.into_iter().collect()
    }

    fn is_match(&self, pattern: &str, text: &str) -> bool {
        self.regex.get(pattern).is_some_and(|r| r.is_match(text))
    }

    fn rule_matches(&self, rule: &Rule, o: &Observation) -> bool {
        let http = o.http.as_ref();
        match rule {
            Rule::Header { name, regex } => http
                .and_then(|h| h.headers.get(&name.to_ascii_lowercase()))
                .is_some_and(|v| regex.as_ref().is_none_or(|r| self.is_match(r, v))),
            Rule::Cookie { name } => http.is_some_and(|h| {
                h.cookie_names().any(|c| match name.strip_suffix('*') {
                    Some(prefix) => c
                        .to_ascii_lowercase()
                        .starts_with(&prefix.to_ascii_lowercase()),
                    None => c.eq_ignore_ascii_case(name),
                })
            }),
            Rule::Body { regex } => http.is_some_and(|h| self.is_match(regex, &h.body)),
            Rule::Title { regex } => http
                .and_then(|h| h.title.as_deref())
                .is_some_and(|t| self.is_match(regex, t)),
            Rule::Path {
                path,
                status,
                body_regex,
            } => http.and_then(|h| h.extra_paths.get(path)).is_some_and(|p| {
                let status_ok = if status.is_empty() {
                    (200..400).contains(&p.status)
                } else {
                    status.contains(&p.status)
                };
                status_ok
                    && body_regex
                        .as_ref()
                        .is_none_or(|r| self.is_match(r, &p.body))
            }),
            Rule::FaviconSha256 { hash } => http
                .and_then(|h| h.extra_paths.get("/favicon.ico"))
                .and_then(|p| p.sha256.as_deref())
                .is_some_and(|s| s.eq_ignore_ascii_case(hash)),
            Rule::Service { regex } => self.is_match(regex, &service_text(o)),
            Rule::Hostname { regex } => o
                .hostname
                .as_deref()
                .is_some_and(|h| self.is_match(regex, h)),
            Rule::Port { port } => o.port == *port,
        }
    }

    fn extract_version(&self, v: &VersionRule, o: &Observation) -> Option<String> {
        let http = o.http.as_ref();
        let text: String = match v.source {
            VersionSource::Body => http?.body.clone(),
            VersionSource::Title => http?.title.clone()?,
            VersionSource::Header => http?
                .headers
                .get(&v.header.as_ref()?.to_ascii_lowercase())?
                .clone(),
            VersionSource::Service => service_text(o),
        };
        let re = self.regex.get(&v.regex)?;
        re.captures(&text)?.get(1).map(|m| m.as_str().to_string())
    }

    /// Dopasowuje wszystkie sygnatury do obserwacji.
    /// Pewność = bazowa pewność sygnatury × (0.6 + 0.4 × udział spełnionych reguł).
    pub fn evaluate(&self, o: &Observation) -> Vec<Detection> {
        let mut out = Vec::new();
        for sig in &self.sigs {
            if sig.rules.is_empty() {
                continue;
            }
            let matched: Vec<&Rule> = sig
                .rules
                .iter()
                .filter(|r| self.rule_matches(r, o))
                .collect();
            let hit = match sig.mode {
                MatchMode::Any => !matched.is_empty(),
                MatchMode::All => matched.len() == sig.rules.len(),
            };
            if !hit {
                continue;
            }
            let ratio = matched.len() as f32 / sig.rules.len() as f32;
            let confidence = (f32::from(sig.confidence) * (0.6 + 0.4 * ratio))
                .round()
                .min(100.0) as u8;
            out.push(Detection {
                signature_id: sig.id.clone(),
                name: sig.name.clone(),
                category: sig.category.clone(),
                version: sig
                    .version
                    .as_ref()
                    .and_then(|v| self.extract_version(v, o)),
                confidence,
                evidence: matched.iter().map(|r| describe(r)).collect(),
            });
        }
        out
    }
}

fn service_text(o: &Observation) -> String {
    [&o.service, &o.product, &o.version, &o.extra_info]
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

fn describe(r: &Rule) -> String {
    match r {
        Rule::Header { name, .. } => format!("header:{name}"),
        Rule::Cookie { name } => format!("cookie:{name}"),
        Rule::Body { regex } => format!("body~{regex}"),
        Rule::Title { regex } => format!("title~{regex}"),
        Rule::Path { path, .. } => format!("path:{path}"),
        Rule::FaviconSha256 { .. } => "favicon".into(),
        Rule::Service { regex } => format!("service~{regex}"),
        Rule::Hostname { regex } => format!("hostname~{regex}"),
        Rule::Port { port } => format!("port:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asi_core::model::HttpInfo;

    #[test]
    fn matches_wordpress() {
        let yaml = r#"
- id: wordpress
  name: WordPress
  category: cms
  confidence: 90
  rules:
    - type: body
      regex: '/wp-content/'
    - type: cookie
      name: 'wordpress_*'
  version:
    source: body
    regex: 'content="WordPress ([\d.]+)"'
"#;
        let set = SignatureSet::new(SignatureSet::parse_yaml(yaml).unwrap()).unwrap();
        let mut o = Observation::new("10.0.0.1".into(), 80, "tcp".into());
        o.http = Some(HttpInfo {
            status: 200,
            body: r#"<meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/x.css">"#.into(),
            ..Default::default()
        });
        let d = set.evaluate(&o);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].version.as_deref(), Some("6.4.2"));
        assert_eq!(d[0].confidence, 72); // 90 * (0.6 + 0.4 * 0.5)
    }

    #[test]
    fn rejects_paths_leaving_origin() {
        for bad in [
            "//evil.example/x",
            "http://10.0.0.9/",
            "admin",
            "/a\\b",
            "/x@evil",
            "/a b",
        ] {
            assert!(validate_path(bad).is_err(), "{bad}");
        }
        for good in ["/", "/admin", "/wp-login.php", "/server-status?auto"] {
            assert!(validate_path(good).is_ok(), "{good}");
        }
        let yaml = "- id: zla
  name: Zla
  category: x
  rules:
    - type: path
      path: //evil.example/
";
        assert!(SignatureSet::new(SignatureSet::parse_yaml(yaml).unwrap()).is_err());
        let set = SignatureSet::with_stored(Vec::new(), &[("zla".into(), yaml.into())]).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn builtin_signatures_load() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../signatures");
        let set = SignatureSet::new(SignatureSet::load_dir(Path::new(dir)).unwrap()).unwrap();
        assert!(set.len() >= 20);
        assert!(set
            .required_paths()
            .iter()
            .all(|p| validate_path(p).is_ok()));
    }
}

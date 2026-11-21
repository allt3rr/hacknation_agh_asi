//! Cele skanowania: rozpoznawanie IP/CIDR/domen i import z tekstu, CSV lub JSON z raportem.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Ip,
    Cidr,
    Domain,
}

impl TargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::Ip => "ip",
            TargetKind::Cidr => "cidr",
            TargetKind::Domain => "domain",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    pub value: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Wynik parsowania pliku: przyjęte cele (bez duplikatów), odrzucenia z numerem wiersza i liczba duplikatów.
#[derive(Debug, Default, Serialize)]
pub struct ParseReport {
    pub rows: usize,
    pub targets: Vec<Target>,
    pub rejected: Vec<Rejected>,
    pub duplicates: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Rejected {
    pub row: usize,
    pub value: String,
}

impl ParseReport {
    /// Dodaje cel; powtórzony `(kind, value)` zwiększa licznik duplikatów i dokleja nowe tagi.
    fn push(&mut self, index: &mut HashMap<(TargetKind, String), usize>, target: Target) {
        match index.get(&(target.kind, target.value.clone())) {
            Some(&i) => {
                self.duplicates += 1;
                let existing = &mut self.targets[i];
                for tag in target.tags {
                    if !existing.tags.contains(&tag) {
                        existing.tags.push(tag);
                    }
                }
            }
            None => {
                index.insert((target.kind, target.value.clone()), self.targets.len());
                self.targets.push(target);
            }
        }
    }
}

fn domain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$").unwrap()
    })
}

/// Rozpoznaje pojedynczy wpis. `None` dla pustych wpisów, komentarzy i niepoprawnych wartości.
pub fn classify(raw: &str) -> Option<Target> {
    let v = raw.trim();
    if v.is_empty() || v.starts_with('#') {
        return None;
    }
    let (kind, value) = if let Ok(ip) = v.parse::<IpAddr>() {
        (TargetKind::Ip, ip.to_string())
    } else if let Ok(net) = v.parse::<IpNet>() {
        let net = net.trunc();
        if net.prefix_len() == net.max_prefix_len() {
            (TargetKind::Ip, net.addr().to_string())
        } else {
            (TargetKind::Cidr, net.to_string())
        }
    } else if domain_re().is_match(v) {
        (TargetKind::Domain, v.trim_end_matches('.').to_lowercase())
    } else {
        return None;
    };
    Some(Target {
        kind,
        value,
        tags: Vec::new(),
        note: None,
    })
}

/// Tekst: wpisy oddzielone nową linią, przecinkiem, średnikiem lub spacją; `#` zaczyna komentarz.
pub fn parse_text(text: &str) -> ParseReport {
    let mut report = ParseReport::default();
    let mut index = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("");
        for token in line.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            if token.trim().is_empty() {
                continue;
            }
            report.rows += 1;
            match classify(token) {
                Some(t) => report.push(&mut index, t),
                None => report.rejected.push(Rejected {
                    row: i + 1,
                    value: token.trim().to_string(),
                }),
            }
        }
    }
    report
}

/// CSV z nagłówkiem. Format własny: `target[,tags,note]` (tagi oddzielone `;`).
/// Format organizatora: kolumna `ip_address` jest celem, a `subnet_cidr`, `network_zone`
/// i `hostname` stają się tagami — podsieć nie jest rozwijana.
pub fn parse_csv(data: &str) -> Result<ParseReport> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(data.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .context("CSV: brak nagłówka")?
        .iter()
        .map(|h| h.trim_start_matches('\u{feff}').to_ascii_lowercase())
        .collect();
    let col = |name: &str| headers.iter().position(|h| h == name);
    let (target_col, organizer) = match (col("target"), col("ip_address")) {
        (Some(c), _) => (c, false),
        (None, Some(c)) => (c, true),
        _ => bail!("CSV: wymagana kolumna `target` albo `ip_address`"),
    };
    let tags_col = col("tags");
    let note_col = col("note");
    let meta = [
        ("subnet", col("subnet_cidr")),
        ("zone", col("network_zone")),
        ("host", col("hostname")),
    ];

    let mut report = ParseReport::default();
    let mut index = HashMap::new();
    for (i, record) in rdr.records().enumerate() {
        let row = i + 2;
        let record = record.with_context(|| format!("CSV: błąd w wierszu {row}"))?;
        let field = |c: Option<usize>| c.and_then(|c| record.get(c)).filter(|v| !v.is_empty());
        let raw = record.get(target_col).unwrap_or("");
        report.rows += 1;
        let Some(mut target) = classify(raw) else {
            report.rejected.push(Rejected {
                row,
                value: raw.to_string(),
            });
            continue;
        };
        if organizer {
            for (prefix, c) in meta {
                if let Some(v) = field(c) {
                    target.tags.push(format!("{prefix}:{v}"));
                }
            }
        } else {
            target.tags = split_list(field(tags_col).unwrap_or(""), ';');
            target.note = field(note_col).map(str::to_string);
        }
        report.push(&mut index, target);
    }
    Ok(report)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum JsonInput {
    List(Vec<JsonItem>),
    Wrapped { targets: Vec<JsonItem> },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum JsonItem {
    Plain(String),
    Full {
        target: String,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        note: Option<String>,
    },
}

/// JSON: `["10.0.0.0/24", …]`, `[{"target": "…", "tags": […], "note": "…"}]` albo `{"targets": […]}`.
pub fn parse_json(data: &str) -> Result<ParseReport> {
    let input: JsonInput = serde_json::from_str(data).context("JSON: nieprawidłowy format")?;
    let items = match input {
        JsonInput::List(v) | JsonInput::Wrapped { targets: v } => v,
    };
    let mut report = ParseReport::default();
    let mut index = HashMap::new();
    for (i, item) in items.into_iter().enumerate() {
        let (raw, tags, note) = match item {
            JsonItem::Plain(s) => (s, Vec::new(), None),
            JsonItem::Full { target, tags, note } => (target, tags, note),
        };
        report.rows += 1;
        match classify(&raw) {
            Some(mut t) => {
                t.tags = tags;
                t.note = note;
                report.push(&mut index, t);
            }
            None => report.rejected.push(Rejected {
                row: i + 1,
                value: raw,
            }),
        }
    }
    Ok(report)
}

/// `csv` | `json` | inne = tekst.
pub fn parse_by_format(format: &str, data: &str) -> Result<ParseReport> {
    match format.to_ascii_lowercase().as_str() {
        "csv" => parse_csv(data),
        "json" => parse_json(data),
        _ => Ok(parse_text(data)),
    }
}

pub fn split_list(s: &str, sep: char) -> Vec<String> {
    s.split(sep)
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_inputs() {
        assert_eq!(classify("10.0.0.1").unwrap().kind, TargetKind::Ip);
        assert_eq!(classify("10.0.0.5/24").unwrap().value, "10.0.0.0/24");
        assert_eq!(classify("10.0.0.7/32").unwrap().kind, TargetKind::Ip);
        assert_eq!(
            classify("Intranet.AGH.edu.pl.").unwrap().value,
            "intranet.agh.edu.pl"
        );
        assert!(classify("nie-adres").is_none());
        assert!(classify("# komentarz").is_none());
    }

    #[test]
    fn text_report_counts_duplicates_and_rejects() {
        let r = parse_text("10.0.0.1, 10.0.0.0/24\nIntranet.AGH.edu.pl\nxx 10.0.0.1 # komentarz");
        assert_eq!(r.rows, 5);
        assert_eq!(r.targets.len(), 3);
        assert_eq!(r.duplicates, 1);
        assert_eq!(
            r.rejected,
            vec![Rejected {
                row: 3,
                value: "xx".into()
            }]
        );
    }

    #[test]
    fn own_csv_format() {
        let r = parse_csv("target,tags,note\n10.0.0.1,dmz;web,serwer www\nxx,,\n").unwrap();
        assert_eq!(r.targets[0].tags, vec!["dmz", "web"]);
        assert_eq!(r.targets[0].note.as_deref(), Some("serwer www"));
        assert_eq!(r.rejected[0].row, 3);
    }

    #[test]
    fn organizer_csv_uses_row_address_and_tags_subnet() {
        let csv = "record_id,ip_address,subnet_cidr,hostname,port,network_zone\n\
                   1,10.10.10.3,10.10.10.0/24,db-prod-003.prod.corp.local,443,PROD\n\
                   2,10.10.10.3,10.10.10.0/24,db-prod-003.prod.corp.local,587,PROD\n\
                   3,10.10.20.9,10.10.20.0/24,,22,DMZ\n";
        let r = parse_csv(csv).unwrap();
        assert_eq!(r.rows, 3);
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.targets.len(), 2);
        assert_eq!(r.targets[0].value, "10.10.10.3");
        assert_eq!(r.targets[0].kind, TargetKind::Ip);
        assert_eq!(
            r.targets[0].tags,
            vec![
                "subnet:10.10.10.0/24",
                "zone:PROD",
                "host:db-prod-003.prod.corp.local"
            ]
        );
        assert_eq!(r.targets[1].tags, vec!["subnet:10.10.20.0/24", "zone:DMZ"]);
    }

    #[test]
    fn organizer_10k_file() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../network_addresses_services_10k.csv"
        );
        let Ok(data) = std::fs::read_to_string(path) else {
            eprintln!("pominięto: brak {path}");
            return;
        };
        let r = parse_csv(&data).unwrap();
        assert_eq!(
            (r.rows, r.targets.len(), r.duplicates, r.rejected.len()),
            (10000, 2800, 7200, 0)
        );
    }

    #[test]
    fn csv_without_target_column_fails() {
        assert!(parse_csv("foo,bar\n1,2\n").is_err());
    }

    #[test]
    fn json_formats() {
        let r = parse_json(
            r#"{"targets": ["10.0.0.0/29", {"target": "a.pl", "tags": ["x"]}, "zle!"]}"#,
        )
        .unwrap();
        assert_eq!(r.targets.len(), 2);
        assert_eq!(r.targets[1].tags, vec!["x"]);
        assert_eq!(r.rejected[0].row, 3);
    }
}

/// Rozwija cele do wejść nmap: CIDR → adresy hostów, IP i domeny bez zmian; bez duplikatów.
/// Przekroczenie `max` (np. `scan.max_targets`) lub zakres większy niż /8 to błąd.
pub fn expand(targets: &[Target], max: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for t in targets {
        match t.kind {
            TargetKind::Cidr => {
                let net: IpNet = t.value.parse()?;
                let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
                if host_bits > 24 {
                    bail!("Zakres {} jest zbyt duży (limit /8 dla IPv4)", t.value);
                }
                if out.len() + (1usize << host_bits) > max + 2 {
                    bail!("Przekroczono limit {max} celów przy {}", t.value);
                }
                for ip in net.hosts() {
                    let s = ip.to_string();
                    if seen.insert(s.clone()) {
                        out.push(s);
                    }
                }
            }
            TargetKind::Ip | TargetKind::Domain => {
                if seen.insert(t.value.clone()) {
                    out.push(t.value.clone());
                }
            }
        }
    }
    if out.len() > max {
        bail!("Przekroczono limit {max} celów");
    }
    Ok(out)
}

#[cfg(test)]
mod expand_tests {
    use super::*;

    #[test]
    fn expands_cidr_and_limits() {
        let r = parse_text("192.168.1.0/30, example.com 192.168.1.1");
        assert_eq!(
            expand(&r.targets, 100).unwrap(),
            vec!["192.168.1.1", "192.168.1.2", "example.com"]
        );
        assert!(expand(&parse_text("10.0.0.0/24").targets, 100).is_err());
        assert!(expand(&parse_text("10.0.0.0/7").targets, usize::MAX).is_err());
    }
}

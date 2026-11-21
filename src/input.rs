//! Wczytywanie celów (IP, CIDR, domeny) z tekstu, CSV lub JSON.

use crate::model::{Target, TargetKind};
use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

fn domain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$").unwrap()
    })
}

/// Rozpoznaje pojedynczy wpis. Zwraca None dla pustych linii, komentarzy i śmieci.
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
        value,
        kind,
        tags: Vec::new(),
        note: None,
    })
}

/// Tekst wpisany ręcznie: wpisy oddzielone nową linią, przecinkiem, średnikiem lub spacją.
/// Wszystko po `#` w linii jest komentarzem.
pub fn parse_text(text: &str) -> (Vec<Target>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        for token in line.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
            let t = token.trim();
            if t.is_empty() {
                continue;
            }
            match classify(t) {
                Some(target) => ok.push(target),
                None => bad.push(t.to_string()),
            }
        }
    }
    (ok, bad)
}

#[derive(Deserialize)]
struct CsvRow {
    target: String,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

/// CSV z nagłówkiem: `target,tags,note` (tagi rozdzielone `;`).
pub fn parse_csv(data: &str) -> Result<(Vec<Target>, Vec<String>)> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(data.as_bytes());
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for (i, row) in rdr.deserialize::<CsvRow>().enumerate() {
        let row = row.with_context(|| format!("CSV: błąd w wierszu {}", i + 2))?;
        match classify(&row.target) {
            Some(mut t) => {
                t.tags = split_list(row.tags.as_deref().unwrap_or(""), ';');
                t.note = row.note.filter(|n| !n.is_empty());
                ok.push(t);
            }
            None => bad.push(row.target),
        }
    }
    Ok((ok, bad))
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

/// JSON: `["10.0.0.0/24", ...]`, `[{"target": "...", "tags": [...], "note": "..."}]`
/// albo `{"targets": [...]}`.
pub fn parse_json(data: &str) -> Result<(Vec<Target>, Vec<String>)> {
    let input: JsonInput = serde_json::from_str(data).context("JSON: nieprawidłowy format")?;
    let items = match input {
        JsonInput::List(v) => v,
        JsonInput::Wrapped { targets } => targets,
    };
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for item in items {
        let (raw, tags, note) = match item {
            JsonItem::Plain(s) => (s, Vec::new(), None),
            JsonItem::Full { target, tags, note } => (target, tags, note),
        };
        match classify(&raw) {
            Some(mut t) => {
                t.tags = tags;
                t.note = note;
                ok.push(t);
            }
            None => bad.push(raw),
        }
    }
    Ok((ok, bad))
}

/// Wybór parsera po formacie ("csv" | "json" | cokolwiek innego = tekst).
pub fn parse_by_format(format: &str, data: &str) -> Result<(Vec<Target>, Vec<String>)> {
    match format.to_ascii_lowercase().as_str() {
        "csv" => parse_csv(data),
        "json" => parse_json(data),
        _ => Ok(parse_text(data)),
    }
}

/// Rozwija zakresy CIDR do listy adresów. Domeny zostają jako nazwy, rozwiąże je nmap.
pub fn expand(targets: &[Target], max: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for t in targets {
        match t.kind {
            TargetKind::Cidr => {
                let net: IpNet = t.value.parse()?;
                let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
                if host_bits > 24 {
                    bail!("Zakres {} jest zbyt duży (limit /8 dla IPv4)", t.value);
                }
                if out.len() + (1usize << host_bits) > max {
                    bail!("Przekroczono limit {max} celów (scan.max_targets) przy {}", t.value);
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
        bail!("Przekroczono limit {max} celów (scan.max_targets)");
    }
    Ok(out)
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
        assert_eq!(classify("10.0.0.0/24").unwrap().kind, TargetKind::Cidr);
        assert_eq!(classify("10.0.0.7/32").unwrap().kind, TargetKind::Ip);
        assert_eq!(classify("Intranet.AGH.edu.pl").unwrap().value, "intranet.agh.edu.pl");
        assert!(classify("nie-adres").is_none());
        assert!(classify("# komentarz").is_none());
    }

    #[test]
    fn expands_cidr() {
        let (t, _) = parse_text("192.168.1.0/30, example.com");
        let ips = expand(&t, 100).unwrap();
        assert_eq!(ips, vec!["192.168.1.1", "192.168.1.2", "example.com"]);
    }

    #[test]
    fn parses_csv_and_json() {
        let (c, bad) = parse_csv("target,tags,note\n10.0.0.1,dmz;web,serwer www\nxx,,\n").unwrap();
        assert_eq!(c[0].tags, vec!["dmz", "web"]);
        assert_eq!(bad, vec!["xx"]);
        let (j, _) = parse_json(r#"{"targets": ["10.0.0.0/29", {"target": "a.pl", "tags": ["x"]}]}"#).unwrap();
        assert_eq!(j.len(), 2);
    }
}

//! Eksport / import wyników w JSON i CSV (ten sam format w obie strony).

use crate::db::Annotation;
use crate::model::Observation;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

pub const CSV_HEADER: [&str; 14] = [
    "ip", "hostname", "port", "proto", "state", "service", "product", "version", "http_status", "http_title",
    "technologies", "tags", "severity", "note",
];

pub type Annotations = HashMap<String, Annotation>;

/// Każda obserwacja dostaje pole `annotation` (tagi, priorytet, notatka), jeśli analityk ją opisał.
/// Import ignoruje to pole, więc format działa w obie strony.
pub fn to_json(obs: &[Observation], annotations: &Annotations) -> Result<String> {
    let mut rows = Vec::with_capacity(obs.len());
    for o in obs {
        let mut value = serde_json::to_value(o)?;
        if let Some(annotation) = annotations.get(&o.key()) {
            value["annotation"] = serde_json::to_value(annotation)?;
        }
        rows.push(value);
    }
    Ok(serde_json::to_string_pretty(&rows)?)
}

pub fn to_csv(obs: &[Observation], annotations: &Annotations) -> Result<String> {
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record(CSV_HEADER)?;
    for o in obs {
        let techs = o
            .detections
            .iter()
            .map(|d| match &d.version {
                Some(v) => format!("{} {v}", d.name),
                None => d.name.clone(),
            })
            .collect::<Vec<_>>()
            .join("; ");
        let annotation = annotations.get(&o.key());
        w.write_record([
            o.ip.clone(),
            o.hostname.clone().unwrap_or_default(),
            o.port.to_string(),
            o.proto.clone(),
            o.state.clone(),
            o.service.clone().unwrap_or_default(),
            o.product.clone().unwrap_or_default(),
            o.version.clone().unwrap_or_default(),
            o.http.as_ref().map(|h| h.status.to_string()).unwrap_or_default(),
            o.http.as_ref().and_then(|h| h.title.clone()).unwrap_or_default(),
            techs,
            annotation.map(|a| a.tags.join(", ")).unwrap_or_default(),
            annotation.and_then(|a| a.severity.clone()).unwrap_or_default(),
            annotation.and_then(|a| a.note.clone()).unwrap_or_default(),
        ])?;
    }
    let bytes = w.into_inner().map_err(|e| anyhow!("CSV: {e}"))?;
    Ok(String::from_utf8(bytes)?)
}

#[derive(Deserialize)]
struct CsvObs {
    ip: String,
    #[serde(default)]
    hostname: Option<String>,
    port: u16,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

pub fn parse_results(format: &str, data: &str) -> Result<Vec<Observation>> {
    match format.to_ascii_lowercase().as_str() {
        "json" => serde_json::from_str(data).context("JSON: oczekiwano tablicy obserwacji"),
        "csv" => {
            let mut rdr = csv::ReaderBuilder::new().flexible(true).trim(csv::Trim::All).from_reader(data.as_bytes());
            let mut out = Vec::new();
            for (i, row) in rdr.deserialize::<CsvObs>().enumerate() {
                let r = row.with_context(|| format!("CSV: błąd w wierszu {}", i + 2))?;
                let mut o = Observation::new(r.ip, r.port, r.proto.filter(|p| !p.is_empty()).unwrap_or_else(|| "tcp".into()));
                o.hostname = r.hostname;
                if let Some(s) = r.state.filter(|s| !s.is_empty()) {
                    o.state = s;
                }
                o.service = r.service;
                o.product = r.product;
                o.version = r.version;
                out.push(o);
            }
            Ok(out)
        }
        other => bail!("Nieobsługiwany format: {other} (json|csv)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_roundtrip() {
        let mut o = Observation::new("10.0.0.1".into(), 443, "tcp".into());
        o.service = Some("https".into());
        o.product = Some("nginx".into());
        let csv = to_csv(&[o], &Annotations::new()).unwrap();
        let back = parse_results("csv", &csv).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].port, 443);
        assert_eq!(back[0].product.as_deref(), Some("nginx"));
    }

    #[test]
    fn export_includes_annotations_and_reimports() {
        let o = Observation::new("10.0.0.1".into(), 80, "tcp".into());
        let annotation = Annotation {
            key: o.key(),
            tags: vec!["dmz".into()],
            note: Some("sprawdzić".into()),
            severity: Some("high".into()),
            updated_by: "admin".into(),
            updated_at: String::new(),
        };
        let annotations = Annotations::from([(o.key(), annotation)]);

        let csv = to_csv(&[o.clone()], &annotations).unwrap();
        assert!(csv.contains("dmz,high,sprawdzić"));
        assert_eq!(parse_results("csv", &csv).unwrap().len(), 1);

        let json = to_json(&[o], &annotations).unwrap();
        assert!(json.contains("\"severity\": \"high\""));
        assert_eq!(parse_results("json", &json).unwrap().len(), 1);
    }
}

//! Eksport / import wyników w JSON i CSV (ten sam format w obie strony).

use crate::model::Observation;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

pub const CSV_HEADER: [&str; 11] = [
    "ip", "hostname", "port", "proto", "state", "service", "product", "version", "http_status", "http_title",
    "technologies",
];

pub fn to_json(obs: &[Observation]) -> Result<String> {
    Ok(serde_json::to_string_pretty(obs)?)
}

pub fn to_csv(obs: &[Observation]) -> Result<String> {
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
        let csv = to_csv(&[o]).unwrap();
        let back = parse_results("csv", &csv).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].port, 443);
        assert_eq!(back[0].product.as_deref(), Some("nginx"));
    }
}

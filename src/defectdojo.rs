//! Eksport obserwacji do DefectDojo jako findingi informacyjne
//! (endpoint `/api/v2/import-scan/`, typ "Generic Findings Import").
//!
//! TODO: wysyłka surowego XML z nmap jako "Nmap Scan" oraz `reimport-scan`,
//! żeby DefectDojo samo zamykało findingi dla zniknętych usług.

use crate::config::DefectDojoConfig;
use crate::db::Annotation;
use crate::diff::{Change, ChangeKind};
use crate::model::{Detection, Observation};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};
use std::collections::HashMap;

pub async fn push(
    config: &DefectDojoConfig,
    run_id: &str,
    observations: &[Observation],
    changes: &[Change],
    annotations: &HashMap<String, Annotation>,
) -> Result<Value> {
    let token = std::env::var(&config.token_env)
        .with_context(|| format!("Brak tokenu DefectDojo w zmiennej {}", config.token_env))?;

    let report = serde_json::to_vec(&build_report(observations, changes, annotations))?;
    let file = Part::bytes(report)
        .file_name(format!("asi-{run_id}.json"))
        .mime_str("application/json")?;
    let form = Form::new()
        .text("scan_type", "Generic Findings Import")
        .text("engagement", config.engagement_id.to_string())
        .text("minimum_severity", "Info")
        .text("active", "true")
        .text("verified", "false")
        .text("scan_date", today())
        .part("file", file);

    let url = format!("{}/api/v2/import-scan/", config.url.trim_end_matches('/'));
    // timeout: skan czeka na wysyłkę z założoną blokadą, zawieszone DefectDojo nie może jej trzymać w nieskończoność
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?
        .post(url)
        .header("Authorization", format!("Token {token}"))
        .multipart(form)
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("DefectDojo zwróciło {status}: {body}");
    }
    Ok(serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw": body })))
}

/// Raport w formacie Generic Findings Import: detekcje technologii i nowe usługi.
pub fn build_report(observations: &[Observation], changes: &[Change], annotations: &HashMap<String, Annotation>) -> Value {
    let mut findings = Vec::new();

    for obs in observations {
        for detection in &obs.detections {
            findings.push(detection_finding(obs, detection, annotations.get(&obs.key())));
        }
    }
    for change in changes.iter().filter(|c| c.kind == ChangeKind::New) {
        findings.push(new_service_finding(change));
    }

    json!({ "findings": findings })
}

/// Priorytet analityka z adnotacji zamienia domyślne "Info" na poziom DefectDojo.
fn severity(annotation: Option<&Annotation>) -> &'static str {
    match annotation.and_then(|a| a.severity.as_deref()) {
        Some("low") => "Low",
        Some("medium") => "Medium",
        Some("high") => "High",
        Some("critical") => "Critical",
        _ => "Info",
    }
}

fn detection_finding(obs: &Observation, detection: &Detection, annotation: Option<&Annotation>) -> Value {
    let mut description = format!(
        "Wykryto {} (kategoria: {}, pewność: {}%) na {}.\nDowody: {}",
        detection.name,
        detection.category,
        detection.confidence,
        obs.key(),
        detection.evidence.join(", "),
    );
    if let Some(http) = &obs.http {
        let title = http.title.clone().unwrap_or_default();
        description.push_str(&format!("\nHTTP {}: {title}", http.status));
    }
    if let Some(annotation) = annotation {
        if !annotation.tags.is_empty() {
            description.push_str(&format!("\nTagi: {}", annotation.tags.join(", ")));
        }
        if let Some(note) = &annotation.note {
            description.push_str(&format!("\nNotatka analityka: {note}"));
        }
    }

    json!({
        "title": format!("{} na {}:{}", detection.name, obs.ip, obs.port),
        "severity": severity(annotation),
        "date": today(),
        "description": description,
        "component_name": detection.name,
        "component_version": detection.version,
        "unique_id_from_tool": format!("asi|{}|{}", obs.key(), detection.signature_id),
        "endpoints": [{ "host": obs.ip, "port": obs.port }],
    })
}

fn new_service_finding(change: &Change) -> Value {
    json!({
        "title": format!("Nowa usługa: {}", change.key),
        "severity": "Info",
        "date": today(),
        "description": format!("Usługa pojawiła się w najnowszym skanie: {}", change.after.clone().unwrap_or_default()),
        "unique_id_from_tool": format!("asi|new|{}", change.key),
    })
}

fn today() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Detection;

    #[test]
    fn annotation_sets_severity_and_description() {
        let mut obs = Observation::new("10.0.0.1".into(), 80, "tcp".into());
        obs.detections.push(Detection {
            signature_id: "wp".into(),
            name: "WordPress".into(),
            category: "cms".into(),
            version: None,
            confidence: 90,
            evidence: vec![],
        });
        let annotation = Annotation {
            key: obs.key(),
            tags: vec!["dmz".into()],
            note: Some("stary".into()),
            severity: Some("high".into()),
            updated_by: String::new(),
            updated_at: String::new(),
        };

        let plain = build_report(&[obs.clone()], &[], &HashMap::new());
        assert_eq!(plain["findings"][0]["severity"], "Info");

        let annotated = build_report(&[obs.clone()], &[], &HashMap::from([(obs.key(), annotation)]));
        assert_eq!(annotated["findings"][0]["severity"], "High");
        assert!(annotated["findings"][0]["description"].as_str().unwrap().contains("Notatka analityka: stary"));
    }
}

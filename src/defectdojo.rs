//! Eksport obserwacji do DefectDojo jako findingi informacyjne
//! (endpoint `/api/v2/import-scan/`, typ "Generic Findings Import").
//!
//! TODO: wysyłka surowego XML z nmap jako "Nmap Scan" oraz `reimport-scan`,
//! żeby DefectDojo samo zamykało findingi dla zniknętych usług.

use crate::config::DefectDojoConfig;
use crate::diff::{Change, ChangeKind};
use crate::model::{Detection, Observation};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};

pub async fn push(config: &DefectDojoConfig, run_id: &str, observations: &[Observation], changes: &[Change]) -> Result<Value> {
    let token = std::env::var(&config.token_env)
        .with_context(|| format!("Brak tokenu DefectDojo w zmiennej {}", config.token_env))?;

    let report = serde_json::to_vec(&build_report(observations, changes))?;
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
    let response = reqwest::Client::new()
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
pub fn build_report(observations: &[Observation], changes: &[Change]) -> Value {
    let mut findings = Vec::new();

    for obs in observations {
        for detection in &obs.detections {
            findings.push(detection_finding(obs, detection));
        }
    }
    for change in changes.iter().filter(|c| c.kind == ChangeKind::New) {
        findings.push(new_service_finding(change));
    }

    json!({ "findings": findings })
}

fn detection_finding(obs: &Observation, detection: &Detection) -> Value {
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

    json!({
        "title": format!("{} na {}:{}", detection.name, obs.ip, obs.port),
        "severity": "Info",
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

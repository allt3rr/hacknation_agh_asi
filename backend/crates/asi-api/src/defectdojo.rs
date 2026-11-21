//! Eksport do DefectDojo (`/api/v2/import-scan/`, „Generic Findings Import”) na zredagowanych wynikach.

use crate::auth::{AuthUser, ClientIp};
use crate::results::{all_rows, record};
use crate::{ApiError, ApiResult, AppState};
use asi_core::export::ResultRow;
use asi_core::rbac;
use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use reqwest::multipart::{Form, Part};
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DefectDojo {
    pub url: String,
    pub token: String,
    pub engagement: u64,
}

impl DefectDojo {
    /// `ASI_DD_URL`, `ASI_DD_TOKEN`, `ASI_DD_ENGAGEMENT` — wszystkie trzy albo brak integracji.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        Some(Self {
            url: get("ASI_DD_URL").filter(|v| !v.is_empty())?,
            token: get("ASI_DD_TOKEN").filter(|v| !v.is_empty())?,
            engagement: get("ASI_DD_ENGAGEMENT")?.parse().ok()?,
        })
    }
}

/// Findingi: wykryte technologie i nowe usługi; pomija korekty `false_positive`.
pub fn build_report(rows: &[ResultRow], new_keys: &[String]) -> Value {
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let mut findings = Vec::new();
    for r in rows
        .iter()
        .filter(|r| r.status.as_deref() != Some("false_positive"))
    {
        for d in &r.technologies {
            let mut description = format!(
                "Wykryto {} (kategoria: {}, pewność: {}%) na {}.\nDowody: {}",
                d.name,
                d.category,
                d.confidence,
                r.key,
                d.evidence.join(", ")
            );
            if let Some(h) = &r.http {
                description.push_str(&format!(
                    "\nHTTP {}: {}",
                    h.status,
                    h.title.clone().unwrap_or_default()
                ));
            }
            if let Some(owner) = &r.owner {
                description.push_str(&format!("\nWłaściciel: {owner}"));
            }
            findings.push(json!({
                "title": format!("{} na {}:{}", d.name, r.ip, r.port),
                "severity": r.severity.clone().unwrap_or_else(|| "Info".into()),
                "date": today,
                "description": description,
                "component_name": d.name,
                "component_version": d.version,
                "unique_id_from_tool": format!("asi|{}|{}", r.key, d.signature_id),
                "endpoints": [{ "host": r.ip, "port": r.port }],
            }));
        }
    }
    for key in new_keys {
        findings.push(json!({
            "title": format!("Nowa usługa: {key}"),
            "severity": "Info",
            "date": today,
            "description": format!("Usługa pojawiła się w przebiegu: {key}"),
            "unique_id_from_tool": format!("asi|new|{key}"),
        }));
    }
    json!({ "findings": findings })
}

/// Błąd wysyłki: DefectDojo niedostępne lub odrzuciło raport (API: 502) albo błąd wewnętrzny.
pub enum PushError {
    Upstream(String),
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for PushError {
    fn from(e: E) -> Self {
        PushError::Internal(e.into())
    }
}

/// Wysyła zredagowane wyniki przebiegu do DefectDojo. Zwraca liczbę findingów i odpowiedź DefectDojo.
pub async fn push_run(
    st: &AppState,
    dd: &DefectDojo,
    id: Uuid,
) -> Result<(usize, Value), PushError> {
    let rows = all_rows(st, id)
        .await
        .map_err(|e| PushError::Internal(anyhow::anyhow!("{e:?}")))?;
    let new_keys: Vec<String> =
        sqlx::query_scalar("SELECT entity_key FROM changes WHERE run_id = $1 AND kind = 'new'")
            .bind(id)
            .fetch_all(&st.db)
            .await?;
    let report = build_report(&rows, &new_keys);
    let findings = report["findings"].as_array().map_or(0, Vec::len);

    let file = Part::bytes(serde_json::to_vec(&report)?)
        .file_name(format!("asi-{id}.json"))
        .mime_str("application/json")?;
    let form = Form::new()
        .text("scan_type", "Generic Findings Import")
        .text("engagement", dd.engagement.to_string())
        .text("minimum_severity", "Info")
        .text("active", "true")
        .text("verified", "false")
        .text("scan_date", Utc::now().format("%Y-%m-%d").to_string())
        .part("file", file);
    let url = format!("{}/api/v2/import-scan/", dd.url.trim_end_matches('/'));
    // timeout: zawieszone DefectDojo nie może blokować automatycznej wysyłki po skanie w nieskończoność
    let res = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()?
        .post(url)
        .header("Authorization", format!("Token {}", dd.token))
        .multipart(form)
        .send()
        .await
        .map_err(|e| PushError::Upstream(format!("DefectDojo niedostępne: {e}")))?;
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(PushError::Upstream(format!(
            "DefectDojo zwróciło {status}: {body}"
        )));
    }
    let response = serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw": body }));
    Ok((findings, response))
}

/// Automatyczna wysyłka po opublikowanym skanie (gdy DefectDojo jest skonfigurowane).
/// Błąd nie psuje skanu — tylko ostrzeżenie w logu; można ponowić przyciskiem na stronie Skany.
pub async fn push_after_scan(st: &AppState, id: Uuid) {
    let Some(dd) = st.defectdojo.clone() else {
        return;
    };
    match push_run(st, &dd, id).await {
        Ok((findings, _)) => tracing::info!(%id, findings, "wysłano do DefectDojo"),
        Err(PushError::Upstream(e)) => {
            tracing::warn!(%id, error = %e, "wysyłka do DefectDojo nieudana")
        }
        Err(PushError::Internal(e)) => {
            tracing::warn!(%id, error = %e, "wysyłka do DefectDojo nieudana")
        }
    }
}

pub async fn export(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::INTEGRATIONS_EXPORT)?;
    let dd = st.defectdojo.clone().ok_or_else(|| {
        ApiError::Conflict(
            "DefectDojo nie jest skonfigurowane (ASI_DD_URL, ASI_DD_TOKEN, ASI_DD_ENGAGEMENT)"
                .into(),
        )
    })?;
    asi_db::runs::get_run(&st.db, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let (findings, dd_response) = match push_run(&st, &dd, id).await {
        Ok(r) => r,
        Err(PushError::Upstream(m)) => return Err(ApiError::BadGateway(m)),
        Err(PushError::Internal(e)) => return Err(ApiError::Internal(e)),
    };
    record(
        &st,
        &user,
        &ip,
        "defectdojo.export",
        "scan_run",
        id.to_string(),
        json!({ "findings": findings }),
    )
    .await?;
    Ok(Json(
        json!({ "findings": findings, "defectdojo": dd_response }),
    ))
}

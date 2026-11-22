//! Eksport do DefectDojo („Generic Findings Import”) na zredagowanych wynikach, osobno dla każdego IP:
//! aktywny engagement `ASI <ip>` w skonfigurowanym produkcie jest używany ponownie, a gdy go nie ma —
//! tworzony. Wysyłka jest automatyczna i czeka na decyzję o CVE: po sprawdzeniu podatności idzie info
//! z CVE, po odrzuceniu (albo w trybie `off`) samo info.

use crate::auth::{AuthUser, ClientIp};
use crate::results::{all_rows, record};
use crate::{ApiError, ApiResult, AppState};
use asi_core::export::ResultRow;
use asi_core::rbac;
use asi_core::vuln::{Vulnerability, EVIDENCE_BACKPORT, EVIDENCE_CONDITIONAL, EVIDENCE_CONFIRMED};
use axum::extract::{Path, State};
use axum::Json;
use reqwest::multipart::{Form, Part};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

/// Równoległe wysyłki do DefectDojo (zakres = wiele IP = wiele engagementów).
const PARALLEL: usize = 4;
const ACTIVE: &str = "In Progress";

#[derive(Debug, Clone)]
pub struct DefectDojo {
    pub url: String,
    pub token: String,
    /// Produkt, w którym powstają engagementy per IP.
    pub product: u64,
}

impl DefectDojo {
    /// `ASI_DD_URL`, `ASI_DD_TOKEN`, `ASI_DD_PRODUCT` — wszystkie trzy albo brak integracji.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        Some(Self {
            url: get("ASI_DD_URL").filter(|v| !v.is_empty())?,
            token: get("ASI_DD_TOKEN").filter(|v| !v.is_empty())?,
            product: get("ASI_DD_PRODUCT")?.parse().ok()?,
        })
    }

    fn api(&self, path: &str) -> String {
        format!("{}/api/v2/{path}", self.url.trim_end_matches('/'))
    }
}

pub fn engagement_name(ip: &str) -> String {
    format!("ASI {ip}")
}

fn today() -> String {
    OffsetDateTime::now_utc().date().to_string()
}

/// Findingi inwentarza: wykryte technologie i nowe usługi (`ip`, klucz); pomija korekty `false_positive`.
pub fn inventory_findings(
    rows: &[ResultRow],
    new_keys: &[(String, String)],
) -> Vec<(String, Value)> {
    let today = today();
    let mut out = Vec::new();
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
            out.push((
                r.ip.clone(),
                json!({
                    "title": format!("{} na {}:{}", d.name, r.ip, r.port),
                    "severity": r.severity.clone().unwrap_or_else(|| "Info".into()),
                    "date": today,
                    "description": description,
                    "component_name": d.name,
                    "component_version": d.version,
                    "unique_id_from_tool": format!("asi|{}|{}", r.key, d.signature_id),
                    "endpoints": [{ "host": r.ip, "port": r.port }],
                }),
            ));
        }
    }
    for (ip, key) in new_keys {
        out.push((
            ip.clone(),
            json!({
                "title": format!("Nowa usługa: {key}"),
                "severity": "Info",
                "date": today,
                "description": format!("Usługa pojawiła się w przebiegu: {key}"),
                "unique_id_from_tool": format!("asi|new|{key}"),
            }),
        ));
    }
    out
}

/// Findingi CVE. `confirmed` → `verified=true`; korelacja wersji → `verified=false` z adnotacją w opisie.
pub fn vuln_findings(items: &[Vulnerability]) -> Vec<(String, Value)> {
    let today = today();
    items
        .iter()
        .map(|v| {
            let confirmed = v.evidence == EVIDENCE_CONFIRMED;
            let evidence = match v.evidence.as_str() {
                EVIDENCE_CONFIRMED => "Potwierdzona aktywnie (nieinwazyjny szablon CVE).",
                EVIDENCE_BACKPORT => "Wersja pakietu dystrybucji zgodna z bazą CVE (NVD) — dystrybucja mogła przenieść poprawkę wstecz, sprawdź wersję pakietu.",
                EVIDENCE_CONDITIONAL => "Korelacja wersji z bazą CVE (NVD), ale CVE dotyczy tylko konfiguracji z innym komponentem (opis) — wymaga potwierdzenia.",
                _ => "Dokładna wersja upstream zgodna z bazą CVE (NVD) — wymaga potwierdzenia.",
            };
            let score = match v.cvss_score {
                Some(s) => format!("CVSS {s}"),
                None => "bez oceny CVSS".into(),
            };
            let key = v.service_key();
            (
                v.ip.clone(),
                json!({
                    "title": format!("{} w {} {} na {}:{}", v.cve_id, v.component, v.version, v.ip, v.port),
                    "severity": v.severity,
                    "date": today,
                    "description": format!("{}\n\n{} ({score}).\nUsługa: {key}\n{}", v.description, v.cve_id, evidence),
                    "vulnerability_ids": [{ "vulnerability_id": v.cve_id }],
                    "cvssv3": v.cvss_vector,
                    "cvssv3_score": v.cvss_score,
                    "verified": confirmed,
                    "active": true,
                    "component_name": v.component,
                    "component_version": v.version,
                    "references": format!("https://nvd.nist.gov/vuln/detail/{}", v.cve_id),
                    "unique_id_from_tool": format!("asi|{key}|{}", v.cve_id),
                    "endpoints": [{ "host": v.ip, "port": v.port }],
                }),
            )
        })
        .collect()
}

/// Co wysłać: samo info (technologie, nowe usługi) albo info z podatnościami CVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    Inventory,
    All,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngagementRef {
    pub ip: String,
    pub engagement_id: u64,
    pub created: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct PushOutcome {
    pub findings: usize,
    pub engagements: Vec<EngagementRef>,
    pub failed: Vec<Value>,
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

/// Odpowiedź DefectDojo z limitem 1 MiB; błąd HTTP → komunikat z treścią.
async fn read(mut res: reqwest::Response) -> Result<Value, String> {
    let status = res.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err("Odpowiedź DefectDojo przekracza 1 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8_lossy(&bytes);
    if !status.is_success() {
        return Err(format!("DefectDojo zwróciło {status}: {body}"));
    }
    Ok(serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw": body })))
}

/// Aktywny engagement `ASI <ip>` w produkcie albo nowy. Filtr `name` w DefectDojo działa jak
/// „zawiera”, więc nazwę, status i produkt sprawdzamy dokładnie po stronie ASI.
async fn engagement_for(
    http: &reqwest::Client,
    dd: &DefectDojo,
    ip: &str,
) -> Result<(u64, bool), String> {
    let name = engagement_name(ip);
    let product = dd.product.to_string();
    let res = http
        .get(dd.api("engagements/"))
        .header("Authorization", format!("Token {}", dd.token))
        .query(&[
            ("product", product.as_str()),
            ("name", name.as_str()),
            ("status", ACTIVE),
            ("limit", "100"),
        ])
        .send()
        .await
        .map_err(|e| format!("DefectDojo niedostępne: {e}"))?;
    let found = read(res).await?;
    let existing = found["results"].as_array().into_iter().flatten().find(|e| {
        e["name"] == name.as_str()
            && e["status"] == ACTIVE
            && e["product"].as_u64() == Some(dd.product)
    });
    if let Some(id) = existing.and_then(|e| e["id"].as_u64()) {
        return Ok((id, false));
    }
    let start = OffsetDateTime::now_utc().date();
    let end = start.saturating_add(time::Duration::days(365));
    let res = http
        .post(dd.api("engagements/"))
        .header("Authorization", format!("Token {}", dd.token))
        .header("Content-Type", "application/json")
        .body(
            json!({
                "name": name,
                "product": dd.product,
                "status": ACTIVE,
                "engagement_type": "Interactive",
                "target_start": start.to_string(),
                "target_end": end.to_string(),
                "description": format!("Attack Surface Intelligence: wyniki dla {ip}"),
            })
            .to_string(),
        )
        .send()
        .await
        .map_err(|e| format!("DefectDojo niedostępne: {e}"))?;
    let created = read(res).await?;
    let id = created["id"]
        .as_u64()
        .ok_or_else(|| format!("DefectDojo nie zwróciło id engagementu: {created}"))?;
    Ok((id, true))
}

async fn import(
    http: &reqwest::Client,
    dd: &DefectDojo,
    engagement: u64,
    ip: &str,
    findings: Vec<Value>,
) -> Result<(), String> {
    let report = serde_json::to_vec(&json!({ "findings": findings })).map_err(|e| e.to_string())?;
    let file = Part::bytes(report)
        .file_name(format!("asi-{ip}.json"))
        .mime_str("application/json")
        .map_err(|e| e.to_string())?;
    let form = Form::new()
        .text("scan_type", "Generic Findings Import")
        .text("engagement", engagement.to_string())
        .text("minimum_severity", "Info")
        .text("active", "true")
        .text("verified", "false")
        .text("scan_date", today())
        .part("file", file);
    let res = http
        .post(dd.api("import-scan/"))
        .header("Authorization", format!("Token {}", dd.token))
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("DefectDojo niedostępne: {e}"))?;
    read(res).await.map(|_| ())
}

async fn push_ip(
    http: &reqwest::Client,
    dd: &DefectDojo,
    ip: &str,
    findings: Vec<Value>,
) -> Result<EngagementRef, String> {
    let (engagement_id, created) = engagement_for(http, dd, ip).await?;
    import(http, dd, engagement_id, ip, findings).await?;
    Ok(EngagementRef {
        ip: ip.to_string(),
        engagement_id,
        created,
    })
}

/// Wysyła wyniki przebiegu, osobno dla każdego IP. Błąd jednego IP nie przerywa pozostałych;
/// gdy nie udało się nic wysłać, zwraca `Upstream`.
pub async fn push_run(
    st: &AppState,
    dd: &DefectDojo,
    id: Uuid,
    content: Content,
) -> Result<PushOutcome, PushError> {
    let _permit = st
        .exports
        .try_acquire()
        .map_err(|_| PushError::Upstream("Eksport w toku".into()))?;
    let rows = all_rows(st, id)
        .await
        .map_err(|e| PushError::Internal(anyhow::anyhow!("{e:?}")))?;
    let new_keys: Vec<(String, String)> = sqlx::query_as(
        "SELECT host(ip), entity_key FROM changes WHERE run_id = $1 AND kind = 'new' LIMIT 10001",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let mut all = inventory_findings(&rows, &new_keys);
    if content == Content::All {
        all.extend(vuln_findings(
            &crate::vuln::visible(st, id, None, None).await?,
        ));
    }
    let mut by_ip: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (ip, f) in all {
        by_ip.entry(ip).or_default().push(f);
    }
    if let Some((ip, f)) = by_ip.iter().find(|(_, f)| f.len() > 10000) {
        return Err(PushError::Upstream(format!(
            "Raport dla {ip} przekracza limit 10000 wpisów ({})",
            f.len()
        )));
    }

    // timeout: zawieszone DefectDojo nie może blokować automatycznej wysyłki w nieskończoność
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()?;
    let permits = Arc::new(Semaphore::new(PARALLEL));
    let mut tasks = JoinSet::new();
    let mut outcome = PushOutcome::default();
    for (ip, findings) in by_ip {
        outcome.findings += findings.len();
        let (http, dd, permits) = (http.clone(), dd.clone(), permits.clone());
        tasks.spawn(async move {
            let _p = permits.acquire_owned().await;
            let res = push_ip(&http, &dd, &ip, findings).await;
            (ip, res)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        match joined? {
            (_, Ok(e)) => outcome.engagements.push(e),
            (ip, Err(error)) => outcome.failed.push(json!({ "ip": ip, "error": error })),
        }
    }
    outcome.engagements.sort_by(|a, b| a.ip.cmp(&b.ip));
    if outcome.engagements.is_empty() {
        if let Some(first) = outcome.failed.first() {
            return Err(PushError::Upstream(
                first["error"].as_str().unwrap_or_default().to_string(),
            ));
        }
    }
    Ok(outcome)
}

/// `push_run` z zapisem wyniku w przebiegu (`scan_runs.dd_export`), na podstawie którego interfejs
/// pokazuje powiadomienie o przesłaniu. Błąd zapisu wyniku tylko w logu.
async fn push_recorded(
    st: &AppState,
    dd: &DefectDojo,
    id: Uuid,
    content: Content,
) -> Result<PushOutcome, PushError> {
    let res = push_run(st, dd, id, content).await;
    let kind = match content {
        Content::Inventory => "inventory",
        Content::All => "all",
    };
    let result = match &res {
        Ok(o) => json!({
            "content": kind,
            "findings": o.findings,
            "engagements": o.engagements.len(),
            "failed": o.failed.iter().map(|f| f["ip"].clone()).collect::<Vec<_>>(),
            "error": null,
        }),
        Err(PushError::Upstream(e)) => json!({ "content": kind, "error": e }),
        Err(PushError::Internal(e)) => json!({ "content": kind, "error": format!("{e:#}") }),
    };
    if let Err(e) = asi_db::runs::set_dd_export(&st.db, id, &result).await {
        tracing::warn!(%id, error = %e, "zapis wyniku wysyłki do DefectDojo nieudany");
    }
    res
}

/// Automatyczna wysyłka (gdy DefectDojo jest skonfigurowane), dopiero po decyzji o CVE:
/// `All` po sprawdzeniu podatności (info + CVE), `Inventory` gdy sprawdzania nie ma.
/// Błąd nie psuje skanu ani sprawdzania — tylko ostrzeżenie w logu.
pub(crate) async fn push_auto(st: &AppState, id: Uuid, content: Content) {
    let Some(dd) = st.defectdojo.clone() else {
        return;
    };
    match push_recorded(st, &dd, id, content).await {
        Ok(o) => tracing::info!(
            %id,
            findings = o.findings,
            engagements = o.engagements.len(),
            failed = o.failed.len(),
            "wysłano do DefectDojo"
        ),
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
) -> ApiResult<Json<PushOutcome>> {
    user.require(rbac::INTEGRATIONS_EXPORT)?;
    let dd = st.defectdojo.clone().ok_or_else(|| {
        ApiError::Conflict(
            "DefectDojo nie jest skonfigurowane (ASI_DD_URL, ASI_DD_TOKEN, ASI_DD_PRODUCT)".into(),
        )
    })?;
    asi_db::runs::get_run(&st.db, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let outcome = match push_recorded(&st, &dd, id, Content::All).await {
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
        json!({
            "findings": outcome.findings,
            "engagements": outcome.engagements.len(),
            "failed": outcome.failed.len(),
        }),
    )
    .await?;
    Ok(Json(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(evidence: &str, score: Option<f64>) -> Vulnerability {
        Vulnerability {
            ip: "10.0.0.1".into(),
            port: 80,
            proto: "tcp".into(),
            cve_id: "CVE-2021-41773".into(),
            cvss_score: score,
            cvss_vector: score.map(|_| "CVSS:3.1/AV:N".into()),
            severity: asi_core::vuln::severity_from_cvss(score).into(),
            evidence: evidence.into(),
            component: "http_server".into(),
            version: "2.4.49".into(),
            description: "opis".into(),
            published: None,
        }
    }

    #[test]
    fn cve_findings_content() {
        let f = vuln_findings(&[
            vuln("confirmed", Some(9.8)),
            vuln("version_match", None),
            vuln("version_backport", None),
        ]);
        assert!(f[2].1["description"]
            .as_str()
            .unwrap()
            .contains("pakietu dystrybucji"));
        assert_eq!(f[2].1["verified"], false);
        let (ip, c) = &f[0];
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(
            c["vulnerability_ids"][0]["vulnerability_id"],
            "CVE-2021-41773"
        );
        assert_eq!(c["cvssv3_score"], 9.8);
        assert_eq!(c["severity"], "Critical");
        assert_eq!(c["verified"], true);
        assert_eq!(
            c["unique_id_from_tool"],
            "asi|10.0.0.1:80/tcp|CVE-2021-41773"
        );
        let (_, m) = &f[1];
        assert_eq!(m["verified"], false);
        assert_eq!(m["severity"], "Info");
        assert!(m["description"]
            .as_str()
            .unwrap()
            .contains("Dokładna wersja"));
        // ten sam identyfikator przy ponownej wysyłce = brak duplikatów w DefectDojo
        assert_eq!(
            vuln_findings(&[vuln("confirmed", Some(9.8))])[0].1["unique_id_from_tool"],
            c["unique_id_from_tool"]
        );
    }

    #[test]
    fn config_requires_product() {
        let env = |k: &str| match k {
            "ASI_DD_URL" => Some("http://dd".to_string()),
            "ASI_DD_TOKEN" => Some("t".to_string()),
            "ASI_DD_ENGAGEMENT" => Some("7".to_string()),
            _ => None,
        };
        assert!(
            DefectDojo::from_env(env).is_none(),
            "ASI_DD_ENGAGEMENT nie wystarcza"
        );
        let full = |k: &str| env(k).or((k == "ASI_DD_PRODUCT").then(|| "3".to_string()));
        assert_eq!(DefectDojo::from_env(full).unwrap().product, 3);
    }
}

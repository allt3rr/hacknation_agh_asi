//! Sprawdzanie podatności przebiegu: identyfikacja usług → CVE z NVD (cache w bazie) → klasyfikacja
//! CVSS → opcjonalna weryfikacja aktywna (nuclei, w zakresie) → wysyłka do DefectDojo.
//! Tryb po publikacji: `auto` (start), `ask` (`pending_decision`), `off` (nic).

use crate::auth::{AuthUser, ClientIp};
use crate::defectdojo::{push_auto, Content};
use crate::results::record;
use crate::{ApiError, ApiResult, AppState};
use anyhow::{anyhow, Context};
use asi_core::model::Observation;
use asi_core::rbac;
use asi_core::vuln::{identify, CveInfo, ServiceId, Vulnerability, EVIDENCE_CONFIRMED};
use asi_db::audit::{self, Entry};
use asi_db::vulns::{self, Transition};
use asi_db::{overrides, runs, views};
use asi_scanner::config::{ScanConfig, VulnMode};
use asi_scanner::nuclei::{self, NucleiOptions};
use asi_scanner::scope::{PortSet, Scope};
use asi_scanner::CancellationToken;
use asi_vuln::NvdClient;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use uuid::Uuid;

const SEVERITIES: [&str; 5] = ["Critical", "High", "Medium", "Low", "Info"];

/// Po opublikowaniu przebiegu skanu: start sprawdzania, pytanie albo od razu wysyłka samego info
/// do DefectDojo. Przy `auto` i `ask` wysyłka czeka na koniec sprawdzania albo na odrzucenie.
pub async fn after_publish(st: &AppState, run_id: Uuid, mode: VulnMode) {
    let res = match mode {
        VulnMode::Auto => start(st, run_id).await.map(|_| ()),
        VulnMode::Ask => vulns::set_initial(&st.db, run_id, "pending_decision").await,
        VulnMode::Off => {
            push_auto(st, run_id, Content::Inventory).await;
            Ok(())
        }
    };
    if let Err(e) = res {
        tracing::error!(%run_id, error = %e, "sprawdzanie podatności: błąd startu");
    }
}

/// Rezerwuje sprawdzanie (jedno naraz na przebieg) i uruchamia je w tle.
pub async fn start(st: &AppState, run_id: Uuid) -> anyhow::Result<Transition> {
    let t = vulns::begin(&st.db, run_id).await?;
    if t == Transition::Done {
        let st = st.clone();
        tokio::spawn(async move { check(st, run_id).await });
    }
    Ok(t)
}

async fn check(st: AppState, run_id: Uuid) {
    let (state, reason, summary) = match run(&st, run_id).await {
        Ok((summary, reason)) => ("done", reason, summary),
        Err(e) => ("failed", Some(format!("{e:#}")), json!({})),
    };
    if let Err(e) = vulns::finish(&st.db, run_id, state, reason.as_deref(), &summary).await {
        tracing::error!(%run_id, error = %e, "sprawdzanie podatności: zapis stanu nieudany");
        return;
    }
    let entry = Entry {
        user_id: None,
        username: None,
        action: "vuln.check.finish",
        entity: Some("scan_run"),
        entity_id: Some(run_id.to_string()),
        ip: None,
        details: json!({ "state": state, "reason": reason, "summary": summary }),
    };
    if let Err(e) = audit::record(&st.db, entry).await {
        tracing::warn!(%run_id, error = %e, "audit_log: zapis nieudany");
    }
    tracing::info!(%run_id, state, "sprawdzanie podatności zakończone");
    // nieudane sprawdzanie: info i tak trafia do DefectDojo, bez CVE
    let content = if state == "done" {
        Content::All
    } else {
        Content::Inventory
    };
    push_auto(&st, run_id, content).await;
}

/// Wszystkie obserwacje przebiegu (deszyfrowane stronami).
async fn observations(st: &AppState, run_id: Uuid) -> anyhow::Result<Vec<Observation>> {
    let mut out = Vec::new();
    loop {
        let (total, items) =
            views::observations_page(&st.db, &st.crypto, run_id, None, 500, out.len() as i64)
                .await?;
        let n = items.len();
        out.extend(items.into_iter().map(|(_, o)| o));
        if n == 0 || out.len() as i64 >= total {
            return Ok(out);
        }
    }
}

/// Zakres weryfikacji: aktualne (niewykluczone) cele, porty z whitelisty i porty otwarte w przebiegu.
async fn scope_for(st: &AppState, cfg: &ScanConfig, obs: &[Observation]) -> anyhow::Result<Scope> {
    let targets = crate::scans::load_targets(st, None)
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    let allowed = cfg.ports.as_deref().map(PortSet::parse).transpose()?;
    let mut scope = Scope::new(&targets, allowed);
    for o in obs.iter().filter(|o| o.state == "open") {
        let Ok(ip) = o.ip.parse::<IpAddr>() else {
            continue;
        };
        // adres domeny-celu, na który nmap ją rozwiązał w tym przebiegu
        if o.hostname
            .as_deref()
            .is_some_and(|h| scope.is_domain_target(h))
        {
            scope.add_resolved(ip);
        }
        if scope.ip_in_scope(ip) {
            scope.add_open_port(ip, o.port);
        }
    }
    Ok(scope)
}

async fn cves(
    st: &AppState,
    client: &NvdClient,
    cfg: &ScanConfig,
    cpe: &str,
) -> anyhow::Result<Vec<CveInfo>> {
    if let Some(cached) = vulns::cache_get(&st.db, cpe, cfg.vuln.cache_hours).await? {
        if let Ok(items) = serde_json::from_value(cached) {
            return Ok(items);
        }
    }
    let items = client
        .cves_for(cpe)
        .await
        .with_context(|| format!("CVE dla {cpe}"))?;
    vulns::cache_put(&st.db, cpe, &serde_json::to_value(&items)?).await?;
    Ok(items)
}

/// Sprawdzanie. Zwraca podsumowanie i ewentualną uwagę (np. nieudana weryfikacja aktywna).
async fn run(st: &AppState, run_id: Uuid) -> anyhow::Result<(Value, Option<String>)> {
    let cfg = st
        .scans
        .cfg
        .clone()
        .map_err(|e| anyhow!("Błędna konfiguracja skanu: {e}"))?;
    let obs: Vec<Observation> = observations(st, run_id)
        .await?
        .into_iter()
        .filter(|o| o.state == "open")
        .collect();

    let mut services: BTreeMap<String, Vec<(&Observation, ServiceId)>> = BTreeMap::new();
    let mut unidentified = 0;
    for o in &obs {
        match identify(o) {
            Some(id) => services.entry(id.cpe.clone()).or_default().push((o, id)),
            None => unidentified += 1,
        }
    }

    let key = std::env::var("ASI_NVD_API_KEY").ok();
    let client = NvdClient::new(&cfg.vuln.nvd_url, key)?;
    let mut found: Vec<Vulnerability> = Vec::new();
    for (cpe, items) in &services {
        let list = cves(st, &client, &cfg, cpe).await?;
        for (o, id) in items {
            found.extend(asi_vuln::correlate(o, id, &list));
        }
    }
    vulns::replace(&st.db, run_id, &found).await?;

    let mut note = None;
    let mut confirmed = 0;
    if cfg.vuln.verify {
        let scope = scope_for(st, &cfg, &obs).await?;
        let targets = nuclei::select_targets(&obs, &scope);
        let opts = NucleiOptions {
            binary: cfg.vuln.nuclei_binary.clone(),
            rate_limit: cfg.vuln.verify_rate,
        };
        match nuclei::run(&opts, &targets, &CancellationToken::new()).await {
            Ok(hits) => {
                let hits: Vec<_> = hits.into_iter().map(|h| (h.ip, h.port, h.cve_id)).collect();
                confirmed = vulns::confirm(&st.db, run_id, &hits).await?;
            }
            Err(e) => note = Some(format!("weryfikacja aktywna nieudana: {e:#}")),
        }
    }

    let summary = json!({
        "services": obs.len(),
        "identified": obs.len() - unidentified,
        "unidentified": unidentified,
        "cpes": services.len(),
        "vulnerabilities": found.len(),
        "confirmed": confirmed,
        "verify": cfg.vuln.verify,
    });
    Ok((summary, note))
}

/// Podatności przebiegu bez usług oznaczonych przez analityka jako `false_positive`.
pub(crate) async fn visible(
    st: &AppState,
    run_id: Uuid,
    severity: Option<&str>,
    ip: Option<&str>,
) -> anyhow::Result<Vec<Vulnerability>> {
    let items = vulns::list(&st.db, run_id, severity, ip).await?;
    let mut keys: Vec<String> = items.iter().map(Vulnerability::service_key).collect();
    keys.dedup();
    let active = overrides::active_for(&st.db, &st.crypto, &keys).await?;
    Ok(items
        .into_iter()
        .filter(|v| {
            active
                .get(&v.service_key())
                .and_then(|o| o.get("status"))
                .map(String::as_str)
                != Some("false_positive")
        })
        .collect())
}

// --- trasy ------------------------------------------------------------------------

fn transition_error(t: Transition) -> ApiError {
    match t {
        Transition::Busy => ApiError::Conflict("Sprawdzanie podatności już trwa".into()),
        Transition::NotPublished => {
            ApiError::Conflict("Przebieg nie jest opublikowany (trwa albo się nie udał)".into())
        }
        Transition::NotFound | Transition::Done => ApiError::NotFound,
    }
}

pub async fn start_check(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    user.require(rbac::SCANS_RUN)?;
    match start(&st, id).await? {
        Transition::Done => {
            record(
                &st,
                &user,
                &ip,
                "vuln.check.start",
                "scan_run",
                id.to_string(),
                json!({}),
            )
            .await?;
            Ok(StatusCode::ACCEPTED)
        }
        t => Err(transition_error(t)),
    }
}

pub async fn skip_check(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    user.require(rbac::SCANS_RUN)?;
    match vulns::skip(&st.db, id).await? {
        Transition::Done => {
            record(
                &st,
                &user,
                &ip,
                "vuln.check.skip",
                "scan_run",
                id.to_string(),
                json!({}),
            )
            .await?;
            // bez sprawdzania CVE: do DefectDojo samo info
            let st = st.clone();
            tokio::spawn(async move { push_auto(&st, id, Content::Inventory).await });
            Ok(StatusCode::NO_CONTENT)
        }
        t => Err(transition_error(t)),
    }
}

#[derive(Deserialize)]
pub struct VulnQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    severity: Option<String>,
    ip: Option<String>,
}

pub async fn list(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<VulnQuery>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::READ)?;
    let run = runs::get_run(&st.db, id).await?.ok_or(ApiError::NotFound)?;
    let severity = q.severity.as_deref().filter(|s| !s.is_empty());
    if severity.is_some_and(|s| !SEVERITIES.contains(&s)) {
        return Err(ApiError::BadRequest(
            "severity: Critical, High, Medium, Low albo Info".into(),
        ));
    }
    let ip: Option<IpAddr> = match q.ip.as_deref().filter(|ip| !ip.is_empty()) {
        Some(ip) => Some(
            ip.parse()
                .map_err(|_| ApiError::BadRequest("Niepoprawny adres IP".into()))?,
        ),
        None => None,
    };
    let all = visible(&st, id, None, None).await?;
    let mut by_severity: HashMap<&str, usize> = SEVERITIES.iter().map(|s| (*s, 0)).collect();
    for v in &all {
        *by_severity.entry(v.severity.as_str()).or_default() += 1;
    }
    let confirmed = all
        .iter()
        .filter(|v| v.evidence == EVIDENCE_CONFIRMED)
        .count();
    let filtered: Vec<&Vulnerability> = all
        .iter()
        .filter(|v| severity.is_none_or(|s| v.severity == s))
        .filter(|v| ip.is_none_or(|ip| v.ip.parse::<IpAddr>().ok() == Some(ip)))
        .collect();
    let limit = q.limit.unwrap_or(100).clamp(1, 500) as usize;
    let offset = q.offset.unwrap_or(0).max(0) as usize;
    let items: Vec<&&Vulnerability> = filtered.iter().skip(offset).take(limit).collect();
    Ok(Json(json!({
        "total": filtered.len(),
        "items": items,
        "summary": {
            "state": run.vuln_state,
            "reason": run.vuln_reason,
            "by_severity": by_severity,
            "confirmed": confirmed,
            "unidentified": run.vuln_summary.get("unidentified"),
            "services": run.vuln_summary.get("services"),
        },
    })))
}

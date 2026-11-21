//! Przebiegi skanu: start (rezerwacja w bazie, zadanie w tle z dzierżawą), anulowanie, odczyt
//! i harmonogram. Termin z okna czasowego obejmuje nmap, sondy HTTP i ponowne pomiary.

use crate::auth::{AuthUser, ClientIp};
use crate::{ApiError, ApiResult, AppState};
use asi_core::rbac;
use asi_core::targets::{expand, Target, TargetKind};
use asi_db::audit::{self, Entry};
use asi_db::results::{publish, PublishInput, PublishOutcome};
use asi_db::runs::{self, RunView, HEARTBEAT_SECS};
use asi_fingerprint::SignatureSet;
use asi_scanner::config::{window_decision, ScanConfig, ScheduleConfig, WindowDecision};
use asi_scanner::http::Limits;
use asi_scanner::nmap::{AnyRunner, NmapOptions, NmapRunner};
use asi_scanner::{CancellationToken, Plan, Scanner};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{Local, NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

pub type Clock = Arc<dyn Fn() -> NaiveDateTime + Send + Sync>;

pub struct ScanService {
    /// Błąd konfiguracji (np. błędne okno) blokuje każdy start z komunikatem.
    pub cfg: Result<ScanConfig, String>,
    pub runner: Arc<AnyRunner>,
    pub signatures_dir: PathBuf,
    /// Identyfikator procesu — właściciel dzierżaw.
    pub owner: String,
    pub clock: Clock,
    active: Mutex<HashMap<Uuid, CancellationToken>>,
    /// Harmonogram (okna, częstotliwość): z pliku, a po zapisie z interfejsu z bazy. Czytany przy każdym starcie.
    schedule: RwLock<ScheduleConfig>,
}

impl ScanService {
    pub fn new(
        cfg: Result<ScanConfig, String>,
        runner: AnyRunner,
        signatures_dir: PathBuf,
    ) -> Self {
        let schedule = cfg.as_ref().map(|c| c.schedule.clone()).unwrap_or_default();
        Self {
            cfg,
            runner: Arc::new(runner),
            signatures_dir,
            owner: format!("asi-{}", Uuid::new_v4()),
            clock: Arc::new(|| Local::now().naive_local()),
            active: Mutex::default(),
            schedule: RwLock::new(schedule),
        }
    }

    pub fn schedule(&self) -> ScheduleConfig {
        self.schedule.read().unwrap().clone()
    }

    fn set_schedule(&self, schedule: ScheduleConfig) {
        *self.schedule.write().unwrap() = schedule;
    }

    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Prawdziwy nmap z konfiguracji.
    pub fn nmap_runner(cfg: &ScanConfig) -> AnyRunner {
        AnyRunner::Nmap(NmapRunner(NmapOptions {
            binary: cfg.nmap_binary.clone(),
            ports: cfg.ports.clone(),
            top_ports: cfg.top_ports,
            max_rate: cfg.per_process_rate(),
            host_timeout: cfg.host_timeout.clone(),
        }))
    }
}

impl Default for ScanService {
    fn default() -> Self {
        let cfg = ScanConfig::default();
        let runner = Self::nmap_runner(&cfg);
        Self::new(Ok(cfg), runner, PathBuf::from("signatures"))
    }
}

/// Start przebiegu. `Err(msg)` = odmowa (409): trwa skan, poza oknem, błędna konfiguracja, brak celów.
pub async fn start_run(st: &AppState, triggered_by: Option<Uuid>) -> Result<Uuid, StartError> {
    let svc = st.scans.clone();
    let cfg = svc
        .cfg
        .clone()
        .map_err(|e| StartError::Refused(format!("Błędna konfiguracja skanu: {e}")))?;
    let windows = svc
        .schedule()
        .windows()
        .map_err(|e| StartError::Refused(format!("Błędne okno czasowe: {e:#}")))?;
    let now = (svc.clock)();
    let deadline = match window_decision(&windows, now) {
        WindowDecision::Unrestricted => None,
        WindowDecision::Closed => {
            return Err(StartError::Refused(
                "Poza dozwolonym oknem czasowym skanu".into(),
            ))
        }
        WindowDecision::Until(end) => {
            let left = (end - now).to_std().unwrap_or_default();
            Some(Instant::now() + left)
        }
    };

    let targets = load_targets(st).await?;
    let expanded =
        expand(&targets, cfg.max_targets).map_err(|e| StartError::Refused(e.to_string()))?;
    if expanded.is_empty() {
        return Err(StartError::Refused("Brak celów do skanowania".into()));
    }
    // zaległości z poprzedniego skanu najpierw — tylko te, które nadal są w zakresie
    let attempts = runs::resume_targets(&st.db).await?;
    let in_scope: HashSet<&String> = expanded.iter().collect();
    let attempts: HashMap<String, i32> = attempts
        .into_iter()
        .filter(|(t, _)| in_scope.contains(t))
        .collect();
    let mut queue = expanded.clone();
    queue.sort_by_key(|t| !attempts.contains_key(t));

    let expected_alive: HashSet<String> =
        sqlx::query_scalar("SELECT host(ip) FROM assets WHERE state IN ('active', 'unstable')")
            .fetch_all(&st.db)
            .await
            .map_err(anyhow::Error::from)?
            .into_iter()
            .collect();
    let signatures = load_signatures(st, &svc).await?;

    let profile = json!({ "config": cfg, "targets": expanded.len(), "resumed": attempts.len() });
    let run_id = runs::reserve_scan(&st.db, &svc.owner, triggered_by, &profile)
        .await?
        .ok_or_else(|| StartError::Refused("Trwa inny skan".into()))?;

    let token = CancellationToken::new();
    svc.active.lock().unwrap().insert(run_id, token.clone());
    let plan = Plan {
        targets,
        queue,
        expected_alive,
    };
    let st = st.clone();
    tokio::spawn(async move {
        execute(
            &st, run_id, cfg, signatures, plan, attempts, deadline, token,
        )
        .await;
        st.scans.active.lock().unwrap().remove(&run_id);
    });
    Ok(run_id)
}

#[derive(Debug)]
pub enum StartError {
    Refused(String),
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for StartError {
    fn from(e: E) -> Self {
        StartError::Internal(e.into())
    }
}

async fn load_targets(st: &AppState) -> anyhow::Result<Vec<Target>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, value FROM targets WHERE NOT excluded ORDER BY created_at, value",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(kind, value)| {
            let kind = match kind.as_str() {
                "ip" => TargetKind::Ip,
                "cidr" => TargetKind::Cidr,
                "domain" => TargetKind::Domain,
                _ => return None,
            };
            Some(Target {
                kind,
                value,
                tags: vec![],
                note: None,
            })
        })
        .collect())
}

/// Wbudowane sygnatury z katalogu + zapisane w bazie (niepoprawne zapisane są pomijane).
async fn load_signatures(st: &AppState, svc: &ScanService) -> anyhow::Result<SignatureSet> {
    let builtin = SignatureSet::load_dir(&svc.signatures_dir)?;
    let stored: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT ON (slug) slug, yaml FROM rules WHERE enabled ORDER BY slug, version DESC",
    )
    .fetch_all(&st.db)
    .await?;
    SignatureSet::with_stored(builtin, &stored)
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    st: &AppState,
    run_id: Uuid,
    cfg: ScanConfig,
    signatures: SignatureSet,
    plan: Plan,
    attempts: HashMap<String, i32>,
    deadline: Option<Instant>,
    token: CancellationToken,
) {
    let owner = st.scans.owner.clone();
    let heartbeat = {
        let (db, owner, token) = (st.db.clone(), owner.clone(), token.clone());
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(HEARTBEAT_SECS)) => {}
                    _ = token.cancelled() => return,
                }
                if !runs::heartbeat(&db, run_id, &owner).await.unwrap_or(false) {
                    tracing::warn!(%run_id, "utracona dzierżawa lub anulowanie: przerywam skan");
                    token.cancel();
                    return;
                }
            }
        })
    };

    let scanner = match Scanner::new(cfg.clone(), st.scans.runner.clone(), signatures) {
        Ok(s) => s,
        Err(e) => {
            heartbeat.abort();
            let _ =
                runs::finish_failed(&st.db, run_id, &owner, &format!("błąd skanera: {e}")).await;
            return;
        }
    };
    let limits = Limits {
        deadline,
        cancel: token.clone(),
    };
    let report = scanner.run(plan, limits).await;
    heartbeat.abort();
    if token.is_cancelled() {
        return; // anulowano z API albo utracono dzierżawę: wyniku nie publikujemy
    }

    let deadline_hit = deadline.is_some_and(|d| Instant::now() >= d);
    let (status, reason) = report.status(false, deadline_hit);
    let failed: Vec<(Vec<String>, String)> = report
        .failed
        .iter()
        .map(|f| (f.targets.clone(), f.error.clone()))
        .collect();
    let coverage = json!({
        "planned": report.planned,
        "scanned": report.scanned.len(),
        "pending": report.pending.len(),
        "failed": failed.iter().map(|(t, _)| t.len()).sum::<usize>(),
        "live_hosts": report.live_hosts.len(),
        "services": report.observations.len(),
        "http_probed": report.http_probed,
        "chunks": report.chunks.len(),
    });
    let input = PublishInput {
        observations: &report.observations,
        live: &report.live_hosts,
        scanned: &report.scanned,
        resolved: &report.resolved,
        failed: &failed,
        pending: &report.pending,
        attempts: &attempts,
        max_attempts: cfg.max_chunk_attempts,
        inactive_after: cfg.inactive_after_misses,
        planned: report.planned,
        status: status.as_str(),
        reason: reason.as_deref(),
        coverage,
    };
    for attempt in 1..=3 {
        match publish(&st.db, &st.crypto, run_id, &owner, &input).await {
            Ok(PublishOutcome::Published { changes }) => {
                tracing::info!(%run_id, status = status.as_str(), changes, "przebieg opublikowany");
                crate::defectdojo::push_after_scan(st, run_id).await;
                return;
            }
            Ok(PublishOutcome::LeaseLost) => {
                tracing::warn!(%run_id, "dzierżawa utracona przed publikacją: wynik odrzucony");
                return;
            }
            Err(e) => {
                tracing::error!(%run_id, attempt, error = %e, "publikacja nieudana");
                tokio::time::sleep(Duration::from_millis(500 * attempt)).await;
            }
        }
    }
    let _ = runs::finish_failed(&st.db, run_id, &owner, "błąd zapisu wyniku").await;
}

/// Czy harmonogram powinien uruchomić skan: brak skanów, zaległości (`partial`/`failed`) albo minął odstęp.
pub fn is_due(
    last: Option<(chrono::DateTime<Utc>, String)>,
    every_hours: i64,
    now: chrono::DateTime<Utc>,
) -> bool {
    match last {
        None => true,
        Some((_, status)) if status == "partial" || status == "failed" => true,
        Some((started, _)) => (now - started).num_hours() >= every_hours,
    }
}

/// Wczytuje harmonogram zapisany z interfejsu (jeśli jest) w miejsce sekcji [schedule] z pliku.
pub async fn load_saved_schedule(st: &AppState) {
    match asi_db::schedule::load(&st.db).await {
        Ok(Some(value)) => match serde_json::from_value::<ScheduleConfig>(value) {
            Ok(saved) if validate_schedule(&saved).is_ok() => st.scans.set_schedule(saved),
            _ => tracing::error!("zapisany harmonogram jest niepoprawny; używam konfiguracji z pliku"),
        },
        Ok(None) => {}
        Err(e) => tracing::error!(error = %e, "harmonogram: błąd odczytu bazy"),
    }
}

/// Pętla harmonogramu w `asi serve`. Ustawienia są czytane co minutę, więc zmiana z interfejsu
/// działa bez restartu. Błędna konfiguracja skanu blokuje harmonogram (z logiem).
pub async fn scheduler(st: AppState) {
    if st.scans.cfg.is_err() {
        tracing::error!("harmonogram wyłączony: błędna konfiguracja skanu");
        return;
    }
    load_saved_schedule(&st).await;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let schedule = st.scans.schedule();
        if !schedule.enabled {
            continue;
        }
        let last = match runs::last_scan(&st.db).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "harmonogram: błąd odczytu bazy");
                continue;
            }
        };
        if !is_due(last, schedule.every_hours, Utc::now()) {
            continue;
        }
        match start_run(&st, None).await {
            Ok(id) => tracing::info!(%id, "harmonogram: start skanu"),
            Err(StartError::Refused(msg)) => {
                tracing::debug!(%msg, "harmonogram: skan nie wystartował")
            }
            Err(StartError::Internal(e)) => tracing::error!(error = %e, "harmonogram: błąd startu"),
        }
    }
}

// --- trasy ------------------------------------------------------------------------

/// Częstotliwość: od 1 godziny do 30 dni. Okna muszą się parsować (godziny HH:MM, dni mon..sun).
fn validate_schedule(s: &ScheduleConfig) -> Result<(), String> {
    if !(1..=720).contains(&s.every_hours) {
        return Err("Częstotliwość musi wynosić od 1 do 720 godzin".into());
    }
    s.windows().map(|_| ()).map_err(|e| format!("{e:#}"))
}

pub async fn get_schedule(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<ScheduleConfig>> {
    user.require(rbac::READ)?;
    Ok(Json(st.scans.schedule()))
}

pub async fn put_schedule(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Json(schedule): Json<ScheduleConfig>,
) -> ApiResult<StatusCode> {
    user.require(rbac::SCANS_CONFIGURE)?;
    validate_schedule(&schedule).map_err(ApiError::BadRequest)?;
    let value = serde_json::to_value(&schedule).map_err(anyhow::Error::from)?;
    asi_db::schedule::save(&st.db, &value, user.0.id).await?;
    st.scans.set_schedule(schedule);
    let entry = Entry {
        user_id: Some(user.0.id),
        username: Some(&user.0.username),
        action: "schedule.update",
        entity: Some("scan_schedule"),
        entity_id: None,
        ip: ip.0.map(|i| i.to_string()),
        details: value,
    };
    audit::record(&st.db, entry).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn record(
    st: &AppState,
    user: &AuthUser,
    ip: &ClientIp,
    action: &str,
    id: Uuid,
) -> ApiResult<()> {
    let entry = Entry {
        user_id: Some(user.0.id),
        username: Some(&user.0.username),
        action,
        entity: Some("scan_run"),
        entity_id: Some(id.to_string()),
        ip: ip.0.map(|i| i.to_string()),
        details: json!({}),
    };
    Ok(audit::record(&st.db, entry).await?)
}

pub async fn post_run(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    user.require(rbac::SCANS_RUN)?;
    match start_run(&st, Some(user.0.id)).await {
        Ok(id) => {
            record(&st, &user, &ip, "run.start", id).await?;
            Ok((StatusCode::ACCEPTED, Json(json!({ "run_id": id }))))
        }
        Err(StartError::Refused(msg)) => Err(ApiError::Conflict(msg)),
        Err(StartError::Internal(e)) => Err(ApiError::Internal(e)),
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
}

pub async fn list_runs(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<RunView>>> {
    user.require(rbac::READ)?;
    Ok(Json(
        runs::list_runs(&st.db, q.limit.unwrap_or(50).clamp(1, 500)).await?,
    ))
}

pub async fn get_run(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<RunView>> {
    user.require(rbac::READ)?;
    runs::get_run(&st.db, id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

pub async fn cancel_run(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    user.require(rbac::SCANS_RUN)?;
    if !runs::cancel(&st.db, id).await? {
        return match runs::get_run(&st.db, id).await? {
            Some(_) => Err(ApiError::Conflict("Przebieg nie trwa".into())),
            None => Err(ApiError::NotFound),
        };
    }
    // właściciel w tym procesie przerywa od razu; w innym procesie — przy najbliższym heartbeat
    if let Some(token) = st.scans.active.lock().unwrap().get(&id) {
        token.cancel();
    }
    record(&st, &user, &ip, "run.cancel", id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_rules() {
        let now = Utc::now();
        assert!(is_due(None, 24, now));
        assert!(is_due(Some((now, "partial".into())), 24, now));
        assert!(is_due(Some((now, "failed".into())), 24, now));
        assert!(!is_due(
            Some((now - chrono::Duration::hours(3), "done".into())),
            24,
            now
        ));
        assert!(is_due(
            Some((now - chrono::Duration::hours(25), "done".into())),
            24,
            now
        ));
    }
}

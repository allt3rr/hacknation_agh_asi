//! Przebiegi skanu: start (rezerwacja w bazie, zadanie w tle z dzierżawą), anulowanie, odczyt
//! i harmonogram. Termin z okna czasowego obejmuje nmap, sondy HTTP i ponowne pomiary.

use crate::auth::{AuthUser, ClientIp};
use crate::{ApiError, ApiResult, AppState};
use asi_core::rbac;
use asi_core::targets::{expand, Target, TargetKind};
use asi_db::audit::{self, Entry};
use asi_db::results::{publish, PublishInput, PublishOutcome};
use asi_db::runs::{self, RunView, HEARTBEAT_SECS};
use asi_db::schedule::{ScheduleInput, ScheduleView};
use asi_fingerprint::SignatureSet;
use asi_scanner::config::{
    window_decision, ScanConfig, ScheduleConfig, VulnMode, WindowConfig, WindowDecision,
};
use asi_scanner::http::Limits;
use asi_scanner::nmap::{AnyRunner, NmapOptions, NmapRunner};
use asi_scanner::{CancellationToken, Plan, Scanner};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::{OffsetDateTime, PrimitiveDateTime};
use tokio::time::Instant;
use uuid::Uuid;

pub type Clock = Arc<dyn Fn() -> Option<PrimitiveDateTime> + Send + Sync>;

pub struct ScanService {
    /// Błąd konfiguracji (np. błędne okno) blokuje każdy start z komunikatem.
    pub cfg: Result<ScanConfig, String>,
    pub runner: Arc<AnyRunner>,
    pub signatures_dir: PathBuf,
    /// Identyfikator procesu — właściciel dzierżaw.
    pub owner: String,
    pub clock: Clock,
    active: Mutex<HashMap<Uuid, CancellationToken>>,
}

impl ScanService {
    pub fn new(
        cfg: Result<ScanConfig, String>,
        runner: AnyRunner,
        signatures_dir: PathBuf,
    ) -> Self {
        Self {
            cfg,
            runner: Arc::new(runner),
            signatures_dir,
            owner: format!("asi-{}", Uuid::new_v4()),
            clock: Arc::new(|| {
                OffsetDateTime::now_local()
                    .ok()
                    .map(|t| PrimitiveDateTime::new(t.date(), t.time()))
            }),
            active: Mutex::default(),
        }
    }

    /// Termin z okien czasowych (JSON jak w pozycji harmonogramu): `None` = bez ograniczeń,
    /// `Err` = poza oknem albo błędne okno. Wspólny dla skanu i aktywnej weryfikacji podatności.
    pub fn window_deadline(&self, windows: &serde_json::Value) -> Result<Option<Instant>, String> {
        let windows = parse_windows(windows).map_err(|e| format!("Błędne okno czasowe: {e}"))?;
        let now = (self.clock)().ok_or("Nieznany czas lokalny")?;
        match window_decision(&windows, now) {
            WindowDecision::Unrestricted => Ok(None),
            WindowDecision::Closed => Err("Poza dozwolonym oknem czasowym skanu".into()),
            WindowDecision::Until(end) => {
                let left = std::time::Duration::try_from(end - now).unwrap_or_default();
                Ok(Some(Instant::now() + left))
            }
        }
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
/// `selection`: tylko te cele (id z `targets`); `None` = wszystkie niewykluczone (harmonogram).
/// `vuln_mode`: sprawdzanie podatności po publikacji; `None` = z konfiguracji (`[vuln] mode`).
/// `schedule`: pozycja harmonogramu (jej okna dają termin, id i nazwa trafiają do profilu);
/// start ręczny (`None`) nie jest ograniczany oknami.
pub async fn start_run(
    st: &AppState,
    triggered_by: Option<Uuid>,
    selection: Option<&[Uuid]>,
    vuln_mode: Option<VulnMode>,
    schedule: Option<&ScheduleView>,
) -> Result<Uuid, StartError> {
    if selection.is_some_and(|ids| ids.is_empty()) {
        return Err(StartError::BadRequest("Pusta lista celów".into()));
    }
    let svc = st.scans.clone();
    let cfg = svc
        .cfg
        .clone()
        .map_err(|e| StartError::Refused(format!("Błędna konfiguracja skanu: {e}")))?;
    let no_windows = json!([]);
    let deadline = svc
        .window_deadline(schedule.map_or(&no_windows, |s| &s.windows))
        .map_err(StartError::Refused)?;

    let targets = load_targets(st, selection).await?;
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

    let vuln_mode = vuln_mode.unwrap_or(cfg.vuln.mode);
    let profile = json!({ "config": cfg, "targets": expanded.len(), "resumed": attempts.len(),
                          "selected": selection.map(<[Uuid]>::len), "vuln_mode": vuln_mode,
                          "schedule_id": schedule.map(|s| s.id), "schedule_name": schedule.map(|s| &s.name) });
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
            &st, run_id, cfg, signatures, plan, attempts, deadline, token, vuln_mode,
        )
        .await;
        st.scans.active.lock().unwrap().remove(&run_id);
    });
    Ok(run_id)
}

#[derive(Debug)]
pub enum StartError {
    /// Błędne żądanie (400): pusta lista lub nieznany cel.
    BadRequest(String),
    Refused(String),
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for StartError {
    fn from(e: E) -> Self {
        StartError::Internal(e.into())
    }
}

/// Cele do skanu. Przy wyborze nieznane id → 400; wykluczone są pomijane zawsze.
pub(crate) async fn load_targets(
    st: &AppState,
    selection: Option<&[Uuid]>,
) -> Result<Vec<Target>, StartError> {
    if let Some(ids) = selection {
        let unique: HashSet<&Uuid> = ids.iter().collect();
        let known: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets WHERE id = ANY($1)")
            .bind(ids)
            .fetch_one(&st.db)
            .await?;
        if known != unique.len() as i64 {
            return Err(StartError::BadRequest("Nieznany cel".into()));
        }
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, value FROM targets
         WHERE NOT excluded AND ($1::uuid[] IS NULL OR id = ANY($1))
         ORDER BY created_at, value",
    )
    .bind(selection)
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
pub(crate) async fn load_signatures(
    st: &AppState,
    svc: &ScanService,
) -> anyhow::Result<SignatureSet> {
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
    vuln_mode: VulnMode,
) {
    let owner = st.scans.owner.clone();
    let scanner = match Scanner::new(cfg.clone(), st.scans.runner.clone(), signatures) {
        Ok(s) => s,
        Err(e) => {
            let _ =
                runs::finish_failed(&st.db, run_id, &owner, &format!("błąd skanera: {e}")).await;
            return;
        }
    };
    // heartbeat przedłuża dzierżawę i przy okazji zapisuje postęp do scan_runs.hosts_*
    let heartbeat = {
        let (db, owner, token) = (st.db.clone(), owner.clone(), token.clone());
        let (progress, total) = (scanner.progress(), plan.queue.len() as i32);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(HEARTBEAT_SECS)) => {}
                    _ = token.cancelled() => return,
                }
                let done = progress.load(Ordering::Relaxed) as i32;
                if !runs::heartbeat(&db, run_id, &owner, total, done)
                    .await
                    .unwrap_or(false)
                {
                    tracing::warn!(%run_id, "utracona dzierżawa lub anulowanie: przerywam skan");
                    token.cancel();
                    return;
                }
            }
        })
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
                // wysyłka do DefectDojo zależy od decyzji o CVE (`vuln::after_publish`)
                crate::vuln::after_publish(st, run_id, vuln_mode).await;
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
    last: Option<(time::OffsetDateTime, String)>,
    every_hours: i64,
    now: time::OffsetDateTime,
) -> bool {
    match last {
        None => true,
        Some((_, status)) if status == "partial" || status == "failed" => true,
        Some((started, _)) => (now - started).whole_hours() >= every_hours,
    }
}

/// Okna pozycji z JSON-a; błędne okno to błąd całej pozycji, nie pominięcie.
fn parse_windows(value: &serde_json::Value) -> Result<Vec<asi_scanner::config::Window>, String> {
    let windows: Vec<WindowConfig> =
        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    ScheduleConfig {
        windows,
        ..Default::default()
    }
    .windows()
    .map_err(|e| format!("{e:#}"))
}

/// Włączone i należne pozycje, najpierw te z najstarszym ostatnim przebiegiem (brak = najstarszy).
pub fn due_schedules(all: &[ScheduleView], now: OffsetDateTime) -> Vec<&ScheduleView> {
    let mut due: Vec<&ScheduleView> = all
        .iter()
        .filter(|s| s.enabled)
        .filter(|s| {
            let last = s.last_run_at.zip(s.last_status.clone());
            is_due(last, s.every_hours.into(), now)
        })
        .collect();
    due.sort_by_key(|s| s.last_run_at);
    due
}

/// Pętla harmonogramu w `asi serve`. Pozycje są czytane z bazy co minutę, więc zmiana z interfejsu
/// działa bez restartu. Błędna konfiguracja skanu blokuje harmonogram (z logiem).
pub async fn scheduler(st: AppState) {
    let scan_ok = st.scans.cfg.is_ok();
    if !scan_ok {
        tracing::error!("harmonogram wyłączony: błędna konfiguracja skanu");
    }
    if st.scans.cfg.as_ref().is_ok_and(|c| c.schedule.enabled) {
        tracing::warn!("sekcja [schedule] w konfiguracji skanu jest ignorowana; harmonogram ustawia się w interfejsie (Skany → Harmonogram)");
    }
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        // przebieg po restarcie/awarii procesu zostaje `running` z wygasłą dzierżawą; bez tego UI blokuje start
        match runs::recover_orphans(&st.db).await {
            Ok(0) => {}
            Ok(n) => tracing::warn!(count = n, "osierocone przebiegi oznaczone jako failed"),
            Err(e) => tracing::error!(error = %e, "błąd sprzątania osieroconych przebiegów"),
        }
        if !scan_ok {
            continue;
        }
        if let Err(e) = run_due(&st).await {
            tracing::error!(error = %e, "harmonogram: błąd odczytu bazy");
        }
    }
}

/// Jeden obieg planisty: startuje pierwszą należną pozycję, która może ruszyć (w oknie, ma cele).
pub async fn run_due(st: &AppState) -> anyhow::Result<Option<Uuid>> {
    // trwa skan: pozycje czekają do kolejnego obiegu (recover_orphans już zwolnił martwe dzierżawy)
    if runs::scan_running(&st.db).await? {
        return Ok(None);
    }
    let all = asi_db::schedule::list(&st.db).await?;
    for s in due_schedules(&all, OffsetDateTime::now_utc()) {
        // usunięty cel nie może dać 400 i zablokować pozycji
        let ids = asi_db::schedule::existing_targets(&st.db, &s.target_ids).await?;
        if ids.is_empty() {
            tracing::warn!(schedule = %s.name, "harmonogram: pozycja bez istniejących celów");
            continue;
        }
        let vuln = serde_json::from_value(json!(s.vuln_check)).ok();
        match start_run(st, None, Some(&ids), vuln, Some(s)).await {
            Ok(id) => {
                tracing::info!(%id, schedule = %s.name, "harmonogram: start skanu");
                return Ok(Some(id));
            }
            Err(StartError::Refused(msg) | StartError::BadRequest(msg)) => {
                tracing::debug!(%msg, schedule = %s.name, "harmonogram: skan nie wystartował")
            }
            Err(StartError::Internal(e)) => {
                tracing::error!(error = %e, schedule = %s.name, "harmonogram: błąd startu")
            }
        }
    }
    Ok(None)
}

// --- trasy ------------------------------------------------------------------------

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleBody {
    name: String,
    #[serde(default = "enabled_default")]
    enabled: bool,
    every_hours: i32,
    #[serde(default)]
    windows: Vec<WindowConfig>,
    target_ids: Vec<Uuid>,
    #[serde(default)]
    vuln_check: VulnMode,
}

fn enabled_default() -> bool {
    true
}

/// Nazwa 1–100 znaków, częstotliwość 1–720 h, poprawne okna, co najmniej jeden istniejący cel.
async fn validate_schedule(st: &AppState, b: &ScheduleBody) -> ApiResult<()> {
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest(
            "Nazwa musi mieć od 1 do 100 znaków".into(),
        ));
    }
    if !(1..=720).contains(&b.every_hours) {
        return Err(ApiError::BadRequest(
            "Częstotliwość musi wynosić od 1 do 720 godzin".into(),
        ));
    }
    ScheduleConfig {
        windows: b.windows.clone(),
        ..Default::default()
    }
    .windows()
    .map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    if b.target_ids.is_empty() {
        return Err(ApiError::BadRequest("Wybierz co najmniej jeden cel".into()));
    }
    let unique: HashSet<Uuid> = b.target_ids.iter().copied().collect();
    let existing = asi_db::schedule::existing_targets(&st.db, &b.target_ids).await?;
    if existing.len() != unique.len() {
        return Err(ApiError::BadRequest("Nieznany cel w target_ids".into()));
    }
    Ok(())
}

async fn save_schedule(
    st: &AppState,
    user: &AuthUser,
    ip: &ClientIp,
    id: Option<Uuid>,
    b: ScheduleBody,
) -> ApiResult<ScheduleView> {
    user.require(rbac::SCANS_CONFIGURE)?;
    validate_schedule(st, &b).await?;
    let windows = serde_json::to_value(&b.windows).map_err(anyhow::Error::from)?;
    let vuln = json!(b.vuln_check);
    let input = ScheduleInput {
        name: b.name.trim(),
        enabled: b.enabled,
        every_hours: b.every_hours,
        windows: &windows,
        target_ids: &b.target_ids,
        vuln_check: vuln.as_str().unwrap_or("ask"),
    };
    let (id, action) = match id {
        Some(id) => {
            if !asi_db::schedule::update(&st.db, id, &input, user.0.id).await? {
                return Err(ApiError::NotFound);
            }
            (id, "schedule.update")
        }
        None => (
            asi_db::schedule::create(&st.db, &input, user.0.id).await?,
            "schedule.create",
        ),
    };
    let details = serde_json::to_value(&b).map_err(anyhow::Error::from)?;
    audit_schedule(st, user, ip, action, id, details).await?;
    asi_db::schedule::get(&st.db, id)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn audit_schedule(
    st: &AppState,
    user: &AuthUser,
    ip: &ClientIp,
    action: &str,
    id: Uuid,
    details: serde_json::Value,
) -> ApiResult<()> {
    let entry = Entry {
        user_id: Some(user.0.id),
        username: Some(&user.0.username),
        action,
        entity: Some("scan_schedule"),
        entity_id: Some(id.to_string()),
        ip: ip.0.map(|i| i.to_string()),
        details,
    };
    Ok(audit::record(&st.db, entry).await?)
}

pub async fn list_schedules(
    State(st): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Vec<ScheduleView>>> {
    user.require(rbac::READ)?;
    Ok(Json(asi_db::schedule::list(&st.db).await?))
}

pub async fn create_schedule(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Json(b): Json<ScheduleBody>,
) -> ApiResult<(StatusCode, Json<ScheduleView>)> {
    let saved = save_schedule(&st, &user, &ip, None, b).await?;
    Ok((StatusCode::CREATED, Json(saved)))
}

pub async fn update_schedule(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(b): Json<ScheduleBody>,
) -> ApiResult<Json<ScheduleView>> {
    Ok(Json(save_schedule(&st, &user, &ip, Some(id), b).await?))
}

pub async fn delete_schedule(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    user.require(rbac::SCANS_CONFIGURE)?;
    if !asi_db::schedule::delete(&st.db, id).await? {
        return Err(ApiError::NotFound);
    }
    audit_schedule(&st, &user, &ip, "schedule.delete", id, json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn record(
    st: &AppState,
    user: &AuthUser,
    ip: &ClientIp,
    action: &str,
    id: Uuid,
    details: serde_json::Value,
) -> ApiResult<()> {
    let entry = Entry {
        user_id: Some(user.0.id),
        username: Some(&user.0.username),
        action,
        entity: Some("scan_run"),
        entity_id: Some(id.to_string()),
        ip: ip.0.map(|i| i.to_string()),
        details,
    };
    Ok(audit::record(&st.db, entry).await?)
}

#[derive(Deserialize)]
pub struct StartBody {
    /// Id celów do tego przebiegu; brak = wszystkie niewykluczone.
    target_ids: Option<Vec<Uuid>>,
    /// Sprawdzanie podatności po skanie: auto, ask, off; brak = z konfiguracji.
    vuln_check: Option<VulnMode>,
}

pub async fn post_run(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    user.require(rbac::SCANS_RUN)?;
    // puste body = wszystkie cele; błędny JSON lub UUID = 400 (nie 422 z ekstraktora Json)
    let (selection, vuln_check) = if body.iter().all(u8::is_ascii_whitespace) {
        (None, None)
    } else {
        let b = serde_json::from_slice::<StartBody>(&body)
            .map_err(|e| ApiError::BadRequest(format!("Błędne body: {e}")))?;
        (b.target_ids, b.vuln_check)
    };
    match start_run(&st, Some(user.0.id), selection.as_deref(), vuln_check, None).await {
        Ok(id) => {
            let details =
                json!({ "selected": selection.as_ref().map(Vec::len), "vuln_check": vuln_check });
            record(&st, &user, &ip, "run.start", id, details).await?;
            Ok((StatusCode::ACCEPTED, Json(json!({ "run_id": id }))))
        }
        Err(StartError::BadRequest(msg)) => Err(ApiError::BadRequest(msg)),
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
    record(&st, &user, &ip, "run.cancel", id, json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, every_hours: i32, ago_hours: Option<i64>, enabled: bool) -> ScheduleView {
        let now = OffsetDateTime::now_utc();
        ScheduleView {
            id: Uuid::new_v4(),
            name: name.into(),
            enabled,
            every_hours,
            windows: json!([]),
            target_ids: vec![Uuid::new_v4()],
            vuln_check: "off".into(),
            last_run_at: ago_hours.map(|h| now - time::Duration::hours(h)),
            last_status: ago_hours.map(|_| "done".into()),
            missing_targets: 0,
        }
    }

    #[test]
    fn due_schedules_per_entry_oldest_first() {
        let now = OffsetDateTime::now_utc();
        let all = [
            entry("A", 1, Some(2), true),
            entry("B", 24, Some(2), true),
            entry("C", 1, Some(5), true),
            entry("D", 1, None, false),
        ];
        let names: Vec<&str> = due_schedules(&all, now)
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, ["C", "A"]);
        let fresh = [entry("A", 1, Some(2), true), entry("N", 24, None, true)];
        assert_eq!(due_schedules(&fresh, now)[0].name, "N");
    }

    #[test]
    fn due_rules() {
        let now = OffsetDateTime::now_utc();
        assert!(is_due(None, 24, now));
        assert!(is_due(Some((now, "partial".into())), 24, now));
        assert!(is_due(Some((now, "failed".into())), 24, now));
        assert!(!is_due(
            Some((now - time::Duration::hours(3), "done".into())),
            24,
            now
        ));
        assert!(is_due(
            Some((now - time::Duration::hours(25), "done".into())),
            24,
            now
        ));
    }
}

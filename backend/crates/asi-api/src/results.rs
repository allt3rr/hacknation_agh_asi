//! Wyniki, zmiany, dashboard, odsłonięcie sekretów, eksport, import, korekty i sygnatury.

use crate::auth::{AuthUser, ClientIp};
use crate::{ApiError, ApiResult, AppState};
use asi_core::export::{self, ResultRow};
use asi_core::model::Observation;
use asi_core::rbac;
use asi_db::audit::{self, Entry};
use asi_db::results::{publish, PublishInput, PublishOutcome};
use asi_db::{overrides, rules, runs, views};
use asi_fingerprint::SignatureSet;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

const PAGE_MAX: i64 = 500;

pub(crate) async fn record(
    st: &AppState,
    user: &AuthUser,
    ip: &ClientIp,
    action: &str,
    entity: &str,
    id: String,
    details: Value,
) -> ApiResult<()> {
    let entry = Entry {
        user_id: Some(user.0.id),
        username: Some(&user.0.username),
        action,
        entity: Some(entity),
        entity_id: Some(id),
        ip: ip.0.map(|i| i.to_string()),
        details,
    };
    Ok(audit::record(&st.db, entry).await?)
}

/// Obserwacje → wiersze z redakcją i aktywnymi korektami analityka.
pub(crate) async fn to_rows(
    st: &AppState,
    run_id: Uuid,
    items: Vec<(Uuid, Observation)>,
) -> ApiResult<Vec<ResultRow>> {
    let keys: Vec<String> = items.iter().map(|(_, o)| o.key()).collect();
    let active = overrides::active_for(&st.db, &st.crypto, &keys).await?;
    let empty = HashMap::new();
    Ok(items
        .iter()
        .map(|(id, o)| {
            ResultRow::new(
                id.to_string(),
                run_id.to_string(),
                o,
                active.get(&o.key()).unwrap_or(&empty),
            )
        })
        .collect())
}

/// Wszystkie wiersze przebiegu (stronami po 500, żeby nie deszyfrować wszystkiego naraz w jednym zapytaniu).
pub(crate) async fn all_rows(st: &AppState, run_id: Uuid) -> ApiResult<Vec<ResultRow>> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    let mut offset = 0;
    loop {
        let (total, items) =
            views::observations_page(&st.db, &st.crypto, run_id, None, 32, offset).await?;
        let n = items.len() as i64;
        for row in to_rows(st, run_id, items).await? {
            bytes += serde_json::to_vec(&row)?.len();
            if bytes > 32 * 1024 * 1024 {
                return Err(ApiError::Conflict(
                    "Eksport przekracza limit 32 MiB. Pobierz wyniki stronami.".into(),
                ));
            }
            out.push(row);
        }
        offset += n;
        if n == 0 || offset >= total {
            return Ok(out);
        }
    }
}

async fn existing_run(st: &AppState, id: Uuid) -> ApiResult<()> {
    runs::get_run(&st.db, id)
        .await?
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
pub struct PageQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    ip: Option<String>,
    kind: Option<String>,
}

impl PageQuery {
    fn page(&self) -> (i64, i64) {
        (
            self.limit.unwrap_or(100).clamp(1, PAGE_MAX),
            self.offset.unwrap_or(0).max(0),
        )
    }
}

pub async fn observations(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<PageQuery>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::READ)?;
    existing_run(&st, id).await?;
    let ip =
        q.ip.as_deref()
            .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok());
    let (limit, offset) = q.page();
    let (total, items) =
        views::observations_page(&st.db, &st.crypto, id, ip, limit, offset).await?;
    Ok(Json(
        json!({ "total": total, "items": to_rows(&st, id, items).await? }),
    ))
}

pub async fn changes(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<PageQuery>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::READ)?;
    existing_run(&st, id).await?;
    let (limit, offset) = q.page();
    let (total, items) = views::changes_page(&st.db, id, q.kind.as_deref(), limit, offset).await?;
    Ok(Json(json!({ "total": total, "items": items })))
}

pub async fn dashboard(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require(rbac::READ)?;
    Ok(Json(views::dashboard(&st.db).await?))
}

/// Pełne wartości ciasteczek i nagłówków jednej obserwacji — uprawnienie `results.reveal` i audyt.
pub async fn secrets(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::RESULTS_REVEAL)?;
    let (_, o) = views::observation(&st.db, &st.crypto, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    record(
        &st,
        &user,
        &ip,
        "results.reveal",
        "observation",
        id.to_string(),
        json!({ "key": o.key() }),
    )
    .await?;
    let key = o.key();
    let http = o.http.unwrap_or_default();
    Ok(Json(
        json!({ "key": key, "cookies": http.cookies, "headers": http.headers }),
    ))
}

#[derive(Deserialize)]
pub struct ExportQuery {
    #[serde(default = "default_json")]
    format: String,
    #[serde(default)]
    profile: Option<String>,
}

fn default_json() -> String {
    "json".into()
}

pub async fn export_run(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Query(q): Query<ExportQuery>,
) -> ApiResult<Response> {
    user.require(rbac::EXPORT)?;
    existing_run(&st, id).await?;
    let _permit = st
        .exports
        .try_acquire()
        .map_err(|_| ApiError::Conflict("Eksport w toku".into()))?;
    let rows = all_rows(&st, id).await?;
    let (body, mime, ext) = match q.format.as_str() {
        "csv" => {
            let safe = q.profile.as_deref() != Some("raw");
            (
                export::to_csv(&rows, safe)?,
                "text/csv; charset=utf-8",
                "csv",
            )
        }
        "json" => (export::to_json(&rows)?, "application/json", "json"),
        other => {
            return Err(ApiError::BadRequest(format!(
                "Nieobsługiwany format: {other} (json|csv)"
            )))
        }
    };
    let disposition = format!("attachment; filename=\"asi-{id}.{ext}\"");
    Ok((
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct ImportQuery {
    #[serde(default = "default_json")]
    format: String,
}

pub async fn import_results(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Query(q): Query<ImportQuery>,
    body: String,
) -> ApiResult<Json<Value>> {
    user.require(rbac::TARGETS_CREATE)?;
    let mut observations = export::parse_results(&q.format, &body)
        .map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    let signatures = SignatureSet::load_dir(&st.scans.signatures_dir)
        .and_then(SignatureSet::new)
        .unwrap_or_default();
    for o in observations.iter_mut().filter(|o| o.detections.is_empty()) {
        o.detections = signatures.evaluate(o);
    }
    let live: HashSet<String> = observations.iter().map(|o| o.ip.clone()).collect();
    let owner = st.scans.owner.clone();
    let profile = json!({ "import": q.format, "rows": observations.len() });
    let run_id = runs::reserve_import(&st.db, &owner, Some(user.0.id), &profile).await?;
    let input = PublishInput {
        observations: &observations,
        live: &live,
        scanned: &live,
        resolved: &[],
        failed: &[],
        pending: &[],
        attempts: &HashMap::new(),
        max_attempts: 1,
        inactive_after: st
            .scans
            .cfg
            .as_ref()
            .map(|c| c.inactive_after_misses)
            .unwrap_or(3),
        planned: live.len(),
        status: "done",
        reason: None,
        coverage: json!({ "planned": live.len(), "scanned": live.len(), "services": observations.len(), "import": true }),
    };
    let changes = match publish(&st.db, &st.crypto, run_id, &owner, &input).await? {
        PublishOutcome::Published { changes } => changes,
        PublishOutcome::LeaseLost => return Err(ApiError::Conflict("Import przerwany".into())),
    };
    record(
        &st,
        &user,
        &ip,
        "results.import",
        "scan_run",
        run_id.to_string(),
        json!({ "rows": observations.len() }),
    )
    .await?;
    Ok(Json(
        json!({ "run_id": run_id, "observations": observations.len(), "changes": changes }),
    ))
}

// --- korekty ------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OverrideBody {
    key: String,
    field: String,
    value: String,
    #[serde(default)]
    reason: Option<String>,
}

/// Klucz usługi `ip:port/proto` — w treści lub parametrze zapytania, nie w ścieżce
/// (proxy dekodują `%2F` i rozbijają segment).
fn check_key(key: &str) -> ApiResult<()> {
    let ok = key.rsplit_once(':').is_some_and(|(ip, pp)| {
        ip.parse::<std::net::IpAddr>().is_ok()
            && pp.split_once('/').is_some_and(|(p, proto)| {
                p.parse::<u16>().is_ok() && matches!(proto, "tcp" | "udp")
            })
    });
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "Niepoprawny klucz usługi: {key} (ip:port/proto)"
        )))
    }
}

pub async fn put_override(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Json(b): Json<OverrideBody>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::DATA_UPDATE)?;
    let (key, field) = (b.key.clone(), b.field.clone());
    check_key(&key)?;
    if !overrides::FIELDS.contains(&field.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "Pole {field} nie podlega korekcie (dozwolone: {})",
            overrides::FIELDS.join(", ")
        )));
    }
    if field == "status" && !overrides::STATUSES.contains(&b.value.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "Status: {}",
            overrides::STATUSES.join(", ")
        )));
    }
    let id = overrides::set(
        &st.db,
        &st.crypto,
        &key,
        &field,
        &b.value,
        b.reason.as_deref(),
        user.0.id,
    )
    .await?;
    record(
        &st,
        &user,
        &ip,
        "override.set",
        "service",
        key,
        json!({ "field": field }),
    )
    .await?;
    Ok(Json(json!({ "id": id })))
}

pub async fn delete_override(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Query(q): Query<KeyFieldQuery>,
) -> ApiResult<StatusCode> {
    user.require(rbac::DATA_UPDATE)?;
    let (key, field) = (q.key, q.field);
    if !overrides::revoke(&st.db, &key, &field).await? {
        return Err(ApiError::NotFound);
    }
    record(
        &st,
        &user,
        &ip,
        "override.revoke",
        "service",
        key,
        json!({ "field": field }),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct KeyFieldQuery {
    key: String,
    field: String,
}

#[derive(Deserialize)]
pub struct KeyQuery {
    key: String,
}

pub async fn list_overrides(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<KeyQuery>,
) -> ApiResult<Json<Vec<overrides::OverrideRow>>> {
    user.require(rbac::READ)?;
    Ok(Json(overrides::history(&st.db, &st.crypto, &q.key).await?))
}

// --- sygnatury ------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct YamlBody {
    yaml: String,
}

fn parse_signatures(yaml: &str) -> ApiResult<Vec<asi_fingerprint::Signature>> {
    let sigs =
        SignatureSet::parse_yaml(yaml).map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    SignatureSet::new(sigs.clone()).map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    Ok(sigs)
}

pub async fn list_signatures(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require(rbac::READ)?;
    let builtin: Vec<Value> = SignatureSet::load_dir(&st.scans.signatures_dir)
        .unwrap_or_default()
        .into_iter()
        .map(|s| {
            // ten sam format co przy POST, żeby edycja wbudowanej tworzyła jej nadpisanie
            let yaml = serde_saphyr::to_string(&vec![&s]).unwrap_or_default();
            json!({ "id": s.id, "name": s.name, "category": s.category, "yaml": yaml })
        })
        .collect();
    Ok(Json(
        json!({ "builtin": builtin, "custom": rules::list(&st.db).await? }),
    ))
}

pub async fn create_signatures(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Json(b): Json<YamlBody>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::SIGNATURES_CREATE)?;
    let sigs = parse_signatures(&b.yaml)?;
    let mut created = Vec::new();
    for s in &sigs {
        let yaml = serde_saphyr::to_string(&vec![s]).map_err(anyhow::Error::from)?;
        if !rules::create(&st.db, &s.id, &yaml, user.0.id).await? {
            return Err(ApiError::Conflict(format!(
                "Sygnatura {} już istnieje (użyj PUT, aby dodać wersję)",
                s.id
            )));
        }
        created.push(s.id.clone());
    }
    record(
        &st,
        &user,
        &ip,
        "signature.create",
        "signature",
        created.join(","),
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "created": created })))
}

pub async fn update_signature(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(slug): Path<String>,
    Json(b): Json<YamlBody>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::SIGNATURES_UPDATE)?;
    let sigs = parse_signatures(&b.yaml)?;
    if sigs.len() != 1 || sigs[0].id != slug {
        return Err(ApiError::BadRequest(format!(
            "YAML musi zawierać dokładnie sygnaturę o id {slug}"
        )));
    }
    let yaml = serde_saphyr::to_string(&sigs).map_err(anyhow::Error::from)?;
    if !rules::new_version(&st.db, &slug, &yaml, user.0.id).await? {
        return Err(ApiError::NotFound);
    }
    record(
        &st,
        &user,
        &ip,
        "signature.update",
        "signature",
        slug.clone(),
        json!({}),
    )
    .await?;
    Ok(Json(json!({ "updated": slug })))
}

pub async fn delete_signature(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(slug): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(rbac::SIGNATURES_DELETE)?;
    if !rules::disable(&st.db, &slug).await? {
        return Err(ApiError::NotFound);
    }
    record(
        &st,
        &user,
        &ip,
        "signature.delete",
        "signature",
        slug,
        json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Raport PDF przebiegu do pobrania (uprawnienie i limit równoległości jak eksport JSON/CSV).
pub async fn report_pdf(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> ApiResult<Response> {
    user.require(rbac::EXPORT)?;
    let run = runs::get_run(&st.db, id).await?.ok_or(ApiError::NotFound)?;
    if matches!(run.status.as_str(), "running" | "queued") {
        return Err(ApiError::Conflict(
            "Przebieg jeszcze trwa: raport będzie dostępny po jego zakończeniu".into(),
        ));
    }
    let _permit = st
        .exports
        .try_acquire()
        .map_err(|_| ApiError::Conflict("Eksport w toku".into()))?;
    let rows = all_rows(&st, id).await?;
    let mut changes = Vec::new();
    loop {
        let (total, page) =
            views::changes_page(&st.db, id, None, PAGE_MAX, changes.len() as i64).await?;
        let done = page.is_empty();
        changes.extend(page);
        if done || changes.len() as i64 >= total {
            break;
        }
    }
    let day = run.started_at.unwrap_or(run.created_at).date().to_string();
    let username = user.0.username.clone();
    // składanie PDF jest CPU-bound: poza pulą wątków asynchronicznych
    let pdf = tokio::task::spawn_blocking(move || {
        crate::report::render(&crate::report::ReportInput {
            run: &run,
            rows: &rows,
            changes: &changes,
            generated_by: &username,
            now: time::OffsetDateTime::now_utc(),
        })
    })
    .await
    .map_err(anyhow::Error::from)??;
    let disposition = format!("attachment; filename=\"asi-raport-{day}-{id}.pdf\"");
    Ok((
        [
            (header::CONTENT_TYPE, "application/pdf".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        pdf,
    )
        .into_response())
}

//! Przebiegi skanów: uruchamianie, wyniki, zmiany, porównanie, import, eksport, DefectDojo.

use super::{ApiError, ApiResult};
use crate::auth::{AuthUser, Permission};
use crate::db::{self, RunRow};
use crate::diff::{self, Change};
use crate::model::Observation;
use crate::state::AppState;
use crate::{defectdojo, export, pipeline};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::Instant;

const RUN_LIST_LIMIT: i64 = 100;
const ALL_CHANGES: i64 = 100_000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/runs", get(list_runs).post(start_run))
        .route("/runs/:id", put(update_run))
        .route("/runs/:id/observations", get(run_observations))
        .route("/runs/:id/changes", get(run_changes))
        .route("/runs/:id/export", get(export_run))
        .route("/runs/:id/defectdojo", post(send_to_defectdojo))
        .route("/diff", get(compare_runs))
        .route("/results/import", post(import_results))
}

#[derive(Deserialize)]
struct StartQuery {
    /// Limit czasu skanu w minutach. Po jego upływie skan kończy się jako `partial`.
    max_minutes: Option<u64>,
}

#[derive(Deserialize)]
struct FormatQuery {
    format: Option<String>,
}

#[derive(Deserialize)]
struct UpdateRunRequest {
    note: Option<String>,
}

/// Wysyłka do DefectDojo tylko wybranych usług (klucze `ip:port/proto`). Brak treści = cały skan.
#[derive(Deserialize)]
struct DefectDojoRequest {
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct CompareQuery {
    from: String,
    to: String,
}

async fn list_runs(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<RunRow>>> {
    user.require(Permission::Read)?;
    Ok(Json(db::list_runs(&st.db, &st.crypto, RUN_LIST_LIMIT).await?))
}

async fn update_run(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateRunRequest>,
) -> ApiResult<StatusCode> {
    user.require(Permission::Modify)?;
    let note = req.note.as_deref().map(str::trim).filter(|note| !note.is_empty());
    if !db::update_run_note(&st.db, &st.crypto, &id, note).await? {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn start_run(
    State(st): State<AppState>,
    user: AuthUser,
    Query(query): Query<StartQuery>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    user.require(Permission::RunScan)?;
    if st.scan_running() {
        return Err(ApiError::conflict("Skan już trwa"));
    }

    let deadline = query
        .max_minutes
        .map(|minutes| Instant::now() + Duration::from_secs(minutes * 60));
    let source = format!("manual:{}", user.username);

    tokio::spawn(async move {
        if let Err(error) = pipeline::execute_scan(&st, deadline, &source).await {
            tracing::error!(error = %error, "skan nie powiódł się");
        }
    });

    Ok((StatusCode::ACCEPTED, Json(json!({ "status": "started" }))))
}

async fn run_observations(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<Observation>>> {
    user.require(Permission::Read)?;
    Ok(Json(db::load_observations(&st.db, &st.crypto, &id).await?))
}

async fn run_changes(State(st): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<Json<Vec<Change>>> {
    user.require(Permission::Read)?;
    Ok(Json(db::list_changes(&st.db, &st.crypto, &id, ALL_CHANGES).await?))
}

async fn export_run(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Query(query): Query<FormatQuery>,
) -> ApiResult<Response> {
    user.require(Permission::Read)?;
    let observations = db::load_observations(&st.db, &st.crypto, &id).await?;
    let annotations = db::annotation_map(&st.db, &st.crypto).await?;

    let format = query.format.unwrap_or_else(|| "json".into());
    let (body, content_type) = match format.as_str() {
        "csv" => (export::to_csv(&observations, &annotations)?, "text/csv; charset=utf-8"),
        "json" => (export::to_json(&observations, &annotations)?, "application/json"),
        other => return Err(ApiError::bad_request(format!("Nieobsługiwany format: {other}"))),
    };

    let headers = [
        (header::CONTENT_TYPE, content_type.to_string()),
        (header::CONTENT_DISPOSITION, format!("attachment; filename=\"asi-{id}.{format}\"")),
    ];
    Ok((headers, body).into_response())
}

async fn send_to_defectdojo(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    request: Option<Json<DefectDojoRequest>>,
) -> ApiResult<Json<Value>> {
    user.require(Permission::Create)?;
    let config = st
        .cfg
        .defectdojo
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("DefectDojo nie jest skonfigurowane"))?;

    let mut observations = db::load_observations(&st.db, &st.crypto, &id).await?;
    let mut changes = db::list_changes(&st.db, &st.crypto, &id, ALL_CHANGES).await?;
    let selected: HashSet<String> = request.map(|Json(req)| req.keys.into_iter().collect()).unwrap_or_default();
    if !selected.is_empty() {
        observations.retain(|obs| selected.contains(&obs.key()));
        changes.retain(|change| selected.contains(&change.key));
        if observations.is_empty() {
            return Err(ApiError::bad_request("Żadna z wybranych usług nie należy do tego skanu"));
        }
    }
    let annotations = db::annotation_map(&st.db, &st.crypto).await?;
    let response = defectdojo::push(config, &id, &observations, &changes, &annotations)
        .await
        .map_err(ApiError::bad_request)?;
    Ok(Json(response))
}

/// Porównanie dwóch dowolnych przebiegów.
async fn compare_runs(
    State(st): State<AppState>,
    user: AuthUser,
    Query(query): Query<CompareQuery>,
) -> ApiResult<Json<Vec<Change>>> {
    user.require(Permission::Read)?;
    let before = db::load_observations(&st.db, &st.crypto, &query.from).await?;
    let after = db::load_observations(&st.db, &st.crypto, &query.to).await?;
    let live: HashSet<String> = after.iter().map(|obs| obs.ip.clone()).collect();
    Ok(Json(diff::diff(&before, &after, &live)))
}

/// Import wyników skanu z pliku. Dane przechodzą tę samą ścieżkę co wynik skanera.
async fn import_results(
    State(st): State<AppState>,
    user: AuthUser,
    Query(query): Query<FormatQuery>,
    body: String,
) -> ApiResult<Json<Value>> {
    user.require(Permission::Create)?;

    let format = query.format.unwrap_or_else(|| "json".into());
    let observations = export::parse_results(&format, &body).map_err(ApiError::bad_request)?;
    let source = format!("import-{format}:{}", user.username);
    let run_id = pipeline::import_results(&st, observations, &source)
        .await
        .map_err(ApiError::conflict)?;

    Ok(Json(json!({ "run_id": run_id })))
}

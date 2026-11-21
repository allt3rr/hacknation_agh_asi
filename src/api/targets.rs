use super::{ApiError, ApiResult};
use crate::auth::{AuthUser, Permission};
use crate::db::{self, TargetPatch, TargetView};
use crate::input;
use crate::model::Target;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/targets", get(list_targets).post(add_targets))
        .route("/targets/import", post(import_targets))
        .route("/targets/:id", put(update_target).delete(delete_target))
}

#[derive(Deserialize)]
struct TargetInput {
    value: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct AddTargetsRequest {
    /// Wpisy wpisane ręcznie (oddzielone nową linią, przecinkiem lub spacją).
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    targets: Vec<TargetInput>,
}

#[derive(Deserialize)]
struct ImportQuery {
    format: Option<String>,
}

#[derive(Serialize)]
struct ImportSummary {
    parsed: usize,
    inserted: u64,
    invalid: Vec<String>,
}

async fn list_targets(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<TargetView>>> {
    user.require(Permission::Read)?;
    Ok(Json(db::list_targets(&st.db, &st.crypto).await?))
}

async fn add_targets(
    State(st): State<AppState>,
    user: AuthUser,
    Json(req): Json<AddTargetsRequest>,
) -> ApiResult<Json<ImportSummary>> {
    user.require(Permission::Create)?;

    let (mut targets, mut invalid) = match &req.text {
        Some(text) => input::parse_text(text),
        None => (Vec::new(), Vec::new()),
    };
    for item in req.targets {
        match input::classify(&item.value) {
            Some(target) => targets.push(Target { tags: item.tags, note: item.note, ..target }),
            None => invalid.push(item.value),
        }
    }

    let source = format!("manual:{}", user.username);
    let summary = save_targets(&st, &targets, invalid, &source).await?;
    Ok(Json(summary))
}

async fn import_targets(
    State(st): State<AppState>,
    user: AuthUser,
    Query(query): Query<ImportQuery>,
    body: String,
) -> ApiResult<Json<ImportSummary>> {
    user.require(Permission::Create)?;

    let format = query.format.unwrap_or_else(|| "json".into());
    let (targets, invalid) = input::parse_by_format(&format, &body).map_err(ApiError::bad_request)?;

    let source = format!("import-{format}:{}", user.username);
    let summary = save_targets(&st, &targets, invalid, &source).await?;
    Ok(Json(summary))
}

async fn save_targets(st: &AppState, targets: &[Target], invalid: Vec<String>, source: &str) -> ApiResult<ImportSummary> {
    let inserted = db::insert_targets(&st.db, &st.crypto, targets, source).await?;
    Ok(ImportSummary { parsed: targets.len(), inserted, invalid })
}

async fn update_target(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(patch): Json<TargetPatch>,
) -> ApiResult<StatusCode> {
    user.require(Permission::Modify)?;
    match db::update_target(&st.db, &st.crypto, &id, patch).await? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(ApiError::NotFound),
    }
}

async fn delete_target(State(st): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    user.require(Permission::Delete)?;
    match db::delete_target(&st.db, &id).await? {
        true => Ok(StatusCode::NO_CONTENT),
        false => Err(ApiError::NotFound),
    }
}

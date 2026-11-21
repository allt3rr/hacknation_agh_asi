//! REST API pod `/api` oraz serwowanie zbudowanego frontendu (React).
//! Każdy handler sprawdza uprawnienia roli przez `AuthUser::require`.

mod annotations;
mod dashboard;
mod error;
mod runs;
mod session;
mod settings;
mod signatures;
mod targets;
mod users;

pub use error::{ApiError, ApiResult};

use crate::state::AppState;
use axum::extract::{DefaultBodyLimit, State};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::path::Path;
use tower_http::services::{ServeDir, ServeFile};

const MAX_UPLOAD_BYTES: usize = 64 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .merge(session::routes())
        .merge(dashboard::routes())
        .merge(targets::routes())
        .merge(runs::routes())
        .merge(annotations::routes())
        .merge(signatures::routes())
        .merge(settings::routes())
        .merge(users::routes())
        .fallback(|| async { ApiError::NotFound });

    // Każda ścieżka spoza /api trafia do aplikacji React (routing po stronie klienta).
    let static_dir = Path::new(&state.cfg.server.static_dir);
    let frontend = ServeDir::new(static_dir).not_found_service(ServeFile::new(static_dir.join("index.html")));

    Router::new()
        .nest("/api", api)
        .fallback_service(frontend)
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES))
        .with_state(state)
}

/// Healthcheck dla Dockera. Nie wymaga logowania i nie zwraca danych.
async fn health(State(st): State<AppState>) -> ApiResult<Json<Value>> {
    sqlx::query("SELECT 1").execute(&st.db).await?;
    Ok(Json(json!({ "status": "ok" })))
}

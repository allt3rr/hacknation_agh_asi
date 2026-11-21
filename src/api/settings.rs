//! Konfiguracja skanu z interfejsu: harmonogram (okna czasowe, częstotliwość) i tempo skanowania.

use super::{ApiError, ApiResult};
use crate::auth::{AuthUser, Permission};
use crate::db;
use crate::settings::RuntimeSettings;
use crate::state::{AppState, SETTINGS_KEY};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};

pub fn routes() -> Router<AppState> {
    Router::new().route("/settings", get(get_settings).put(save_settings))
}

async fn get_settings(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<RuntimeSettings>> {
    user.require(Permission::Read)?;
    Ok(Json(st.settings.read().await.clone()))
}

/// Zmiana obowiązuje od następnego skanu; harmonogram widzi ją w ciągu minuty.
async fn save_settings(
    State(st): State<AppState>,
    user: AuthUser,
    Json(settings): Json<RuntimeSettings>,
) -> ApiResult<StatusCode> {
    user.require(Permission::RunScan)?;
    settings.validate().map_err(ApiError::bad_request)?;
    db::save_setting(&st.db, SETTINGS_KEY, &serde_json::to_string(&settings)?).await?;
    *st.settings.write().await = settings;
    tracing::info!(user = %user.username, "zmieniono ustawienia skanu");
    Ok(StatusCode::NO_CONTENT)
}

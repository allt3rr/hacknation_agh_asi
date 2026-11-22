use super::{ApiError, ApiResult};
use crate::auth::{self, AuthUser, Role};
use crate::db;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use time::{Duration, OffsetDateTime};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

// TODO: limit nieudanych prób logowania.
async fn login(
    State(st): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> ApiResult<(CookieJar, Json<Value>)> {
    let user = db::find_user_by_name(&st.db, &req.username)
        .await?
        .filter(|user| auth::verify_password(&req.password, &user.password_hash))
        .ok_or(ApiError::Unauthorized)?;

    let role = Role::parse(&user.role)
        .ok_or_else(|| anyhow::anyhow!("nieznana rola w bazie: {}", user.role))?;
    let hours = st.cfg.server.session_hours;
    let expires_at = (OffsetDateTime::now_utc() + Duration::hours(hours)).unix_timestamp();

    db::delete_expired_sessions(&st.db).await?;
    let token = auth::new_token();
    db::create_session(&st.db, &auth::token_hash(&token), &user.id, expires_at).await?;

    let cookie = auth::session_cookie(token, hours, st.cfg.server.cookie_secure);
    Ok((
        jar.add(cookie),
        Json(json!({ "username": user.username, "role": role })),
    ))
}

/// Zawsze 204 i czyszczenie cookie, także przy wygasłej lub nieznanej sesji.
async fn logout(State(st): State<AppState>, jar: CookieJar) -> ApiResult<(CookieJar, StatusCode)> {
    if let Some(cookie) = jar.get(auth::SESSION_COOKIE) {
        db::delete_session(&st.db, &auth::token_hash(cookie.value())).await?;
    }
    let cleared = auth::cleared_session_cookie(st.cfg.server.cookie_secure);
    Ok((jar.add(cleared), StatusCode::NO_CONTENT))
}

async fn me(user: AuthUser) -> Json<Value> {
    Json(json!({ "username": user.username, "role": user.role }))
}

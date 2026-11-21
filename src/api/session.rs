use super::{ApiError, ApiResult};
use crate::auth::{self, AuthUser, Role, Session};
use crate::db;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
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
async fn login(State(st): State<AppState>, Json(req): Json<LoginRequest>) -> ApiResult<Json<Value>> {
    let user = db::find_user_by_name(&st.db, &req.username)
        .await?
        .filter(|user| auth::verify_password(&req.password, &user.password_hash))
        .ok_or(ApiError::Unauthorized)?;

    let role = Role::parse(&user.role).ok_or_else(|| anyhow::anyhow!("nieznana rola w bazie: {}", user.role))?;
    let token = auth::new_token();
    let session = Session {
        user_id: user.id.clone(),
        username: user.username.clone(),
        role,
        expires: Utc::now() + Duration::hours(st.cfg.server.session_hours),
    };
    st.sessions.write().await.insert(token.clone(), session);

    Ok(Json(json!({ "token": token, "username": user.username, "role": role })))
}

async fn logout(State(st): State<AppState>, user: AuthUser) -> StatusCode {
    st.sessions.write().await.remove(&user.token);
    StatusCode::NO_CONTENT
}

async fn me(user: AuthUser) -> Json<Value> {
    Json(json!({ "username": user.username, "role": user.role }))
}

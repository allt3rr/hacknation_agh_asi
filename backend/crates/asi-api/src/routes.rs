use crate::auth::{cleared_cookie, session_cookie, AuthUser, ClientIp, SESSION_COOKIE};
use crate::{ApiError, ApiResult, AppState};
use asi_core::password::{new_token, token_hash};
use asi_core::rbac;
use asi_db::audit::{self, Entry};
use asi_db::users::Profile;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

pub async fn health(State(st): State<AppState>) -> ApiResult<Json<Value>> {
    sqlx::query("SELECT 1")
        .execute(&st.db)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(json!({ "status": "ok" })))
}

pub async fn auth_config(State(st): State<AppState>) -> Json<Value> {
    Json(json!({ "session_ttl_hours": st.cfg.session_ttl_hours }))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

pub async fn login(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> ApiResult<(CookieJar, Json<Profile>)> {
    let ip = ip.map(|ip| ip.to_string());
    let user_key = format!("user:{}", req.username.to_lowercase());
    let mut keys = vec![user_key.clone()];
    if let Some(ip) = &ip {
        keys.push(format!("ip:{ip}"));
    }
    let audit_entry = |action, user_id| Entry {
        user_id,
        username: Some(req.username.as_str()),
        action,
        entity: None,
        entity_id: None,
        ip: ip.clone(),
        details: json!({}),
    };

    if st.login.is_blocked(&keys) {
        audit::record(&st.db, audit_entry("auth.login_blocked", None)).await?;
        return Err(ApiError::TooManyRequests);
    }

    let creds = asi_db::users::find_credentials(&st.db, &req.username).await?;
    let hash = creds.as_ref().map(|c| c.password_hash.clone());
    let verified = st.login.verify(req.password.clone(), hash).await;

    let creds = match creds {
        Some(c) if verified && !c.disabled => c,
        other => {
            st.login.record_failure(&keys);
            audit::record(
                &st.db,
                audit_entry("auth.login_failed", other.map(|c| c.id)),
            )
            .await?;
            return Err(ApiError::InvalidCredentials);
        }
    };

    asi_db::sessions::delete_expired(&st.db).await?;
    let token = new_token();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let created = asi_db::sessions::create_session(
        &st.db,
        &token_hash(&token),
        creds.id,
        creds.credential_version,
        st.cfg.session_ttl_hours,
        ip.clone(),
        user_agent,
    )
    .await?;
    if !created {
        // hasło zmieniono lub konto wyłączono w trakcie logowania
        audit::record(&st.db, audit_entry("auth.login_failed", Some(creds.id))).await?;
        return Err(ApiError::InvalidCredentials);
    }

    st.login.reset(&user_key);
    audit::record(&st.db, audit_entry("auth.login", Some(creds.id))).await?;
    let profile = asi_db::users::profile(&st.db, creds.id)
        .await?
        .ok_or(ApiError::InvalidCredentials)?;
    let cookie = session_cookie(token, st.cfg.session_ttl_hours, st.cfg.cookie_secure);
    Ok((jar.add(cookie), Json(profile)))
}

/// Zawsze 204 i czyszczenie cookie, także przy wygasłej, nieznanej lub brakującej sesji.
pub async fn logout(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    jar: CookieJar,
) -> ApiResult<(CookieJar, StatusCode)> {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let hash = token_hash(cookie.value());
        let user_id = asi_db::sessions::find_session_user(&st.db, &hash).await?;
        asi_db::sessions::delete_session(&st.db, &hash).await?;
        if user_id.is_some() {
            let entry = Entry {
                user_id,
                username: None,
                action: "auth.logout",
                entity: None,
                entity_id: None,
                ip: ip.map(|i| i.to_string()),
                details: json!({}),
            };
            audit::record(&st.db, entry).await?;
        }
    }
    Ok((
        jar.add(cleared_cookie(st.cfg.cookie_secure)),
        StatusCode::NO_CONTENT,
    ))
}

pub async fn me(user: AuthUser) -> Json<Profile> {
    Json(user.0)
}

/// Endpoint kontrolny do testu macierzy ról.
pub async fn admin_ping(user: AuthUser) -> ApiResult<Json<Value>> {
    user.require(rbac::ADMIN_USERS)?;
    Ok(Json(json!({ "ok": true })))
}

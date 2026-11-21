//! Uwierzytelnianie przez cookie `asi_session` i sprawdzanie uprawnień.

use crate::{ApiError, AppState};
use asi_core::password::token_hash;
use asi_db::users::Profile;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

pub const SESSION_COOKIE: &str = "asi_session";

/// Zalogowany użytkownik z rolami i uprawnieniami odczytanymi z bazy przy tym żądaniu.
#[derive(Debug, Clone)]
pub struct AuthUser(pub Profile);

impl AuthUser {
    /// 403, gdy żadna z ról użytkownika nie daje uprawnienia.
    pub fn require(&self, permission: &str) -> Result<(), ApiError> {
        if self.0.permissions.iter().any(|p| p == permission) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, ApiError> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(SESSION_COOKIE)
            .ok_or(ApiError::Unauthorized)?
            .value();
        let user_id = asi_db::sessions::find_session_user(&st.db, &token_hash(token))
            .await?
            .ok_or(ApiError::Unauthorized)?;
        let profile = asi_db::users::profile(&st.db, user_id)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        Ok(AuthUser(profile))
    }
}

/// Adres klienta z połączenia TCP (nagłówkom typu X-Forwarded-For nie ufamy).
pub struct ClientIp(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(ClientIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip()),
        ))
    }
}

pub fn session_cookie(token: String, hours: i64, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .secure(secure)
        .max_age(time::Duration::hours(hours))
        .build()
}

/// Wysyłane zawsze przy wylogowaniu, także gdy klient nie miał cookie.
pub fn cleared_cookie(secure: bool) -> Cookie<'static> {
    session_cookie(String::new(), 0, secure)
}

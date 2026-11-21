//! Role, uprawnienia, hasła (Argon2) i sesje (tokeny Bearer trzymane w pamięci).

use crate::api::ApiError;
use crate::db;
use crate::state::AppState;
use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Role wymagane w zadaniu:
///
/// - admin: wszystko, łącznie z zarządzaniem użytkownikami,
/// - editor: dodawanie, usuwanie, modyfikacja, skany, sygnatury,
/// - analyst: modyfikacja i odczyt,
/// - viewer: odczyt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Editor,
    Analyst,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Read,
    Modify,
    Create,
    Delete,
    RunScan,
    ManageSignatures,
    ManageUsers,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Editor => "editor",
            Role::Analyst => "analyst",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Role::Admin),
            "editor" => Some(Role::Editor),
            "analyst" => Some(Role::Analyst),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }

    pub fn allows(self, permission: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Admin => true,
            Role::Editor => permission != ManageUsers,
            Role::Analyst => matches!(permission, Read | Modify),
            Role::Viewer => permission == Read,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub username: String,
    pub role: Role,
    pub expires: DateTime<Utc>,
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Przy pierwszym uruchomieniu tworzy konto `admin`.
/// Hasło pochodzi z `ASI_ADMIN_PASSWORD` albo jest generowane i wypisywane w logu.
pub async fn bootstrap_admin(st: &AppState) -> Result<()> {
    if db::count_users(&st.db).await? > 0 {
        return Ok(());
    }

    let (password, generated) = match std::env::var("ASI_ADMIN_PASSWORD") {
        Ok(password) if !password.is_empty() => (password, false),
        _ => (new_token()[..20].to_string(), true),
    };
    db::create_user(&st.db, "admin", &hash_password(&password)?, Role::Admin).await?;

    if generated {
        tracing::warn!("Utworzono konto 'admin' z hasłem: {password}. Zmień je po zalogowaniu.");
    } else {
        tracing::info!("Utworzono konto 'admin' z hasłem z ASI_ADMIN_PASSWORD");
    }
    Ok(())
}

/// Zalogowany użytkownik. Użyty jako argument handlera wymusza ważny token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub role: Role,
}

impl AuthUser {
    pub fn require(&self, permission: Permission) -> Result<(), ApiError> {
        if self.role.allows(permission) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or(ApiError::Unauthorized)?;

        let mut sessions = st.sessions.write().await;
        let session = sessions.get(&token).cloned().ok_or(ApiError::Unauthorized)?;

        if session.expires <= Utc::now() {
            sessions.remove(&token);
            return Err(ApiError::Unauthorized);
        }

        Ok(AuthUser {
            token,
            user_id: session.user_id,
            username: session.username,
            role: session.role,
        })
    }
}

fn bearer_token(parts: &Parts) -> Option<String> {
    let header = parts.headers.get(AUTHORIZATION)?.to_str().ok()?;
    header.strip_prefix("Bearer ").map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_permissions() {
        assert!(Role::Admin.allows(Permission::ManageUsers));
        assert!(!Role::Editor.allows(Permission::ManageUsers));
        assert!(Role::Editor.allows(Permission::Delete));
        assert!(Role::Analyst.allows(Permission::Modify));
        assert!(!Role::Analyst.allows(Permission::Create));
        assert!(Role::Viewer.allows(Permission::Read));
        assert!(!Role::Viewer.allows(Permission::Modify));
    }

    #[test]
    fn password_hashing() {
        let hash = hash_password("tajne-haslo").unwrap();
        assert!(verify_password("tajne-haslo", &hash));
        assert!(!verify_password("zle", &hash));
    }
}

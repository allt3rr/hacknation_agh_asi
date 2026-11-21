use super::{ApiError, ApiResult};
use crate::auth::{self, AuthUser, Permission, Role};
use crate::db::{self, UserRow};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

const MIN_PASSWORD_LENGTH: usize = 10;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route("/users/:id", put(update_user).delete(delete_user))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    role: Role,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    role: Option<Role>,
    password: Option<String>,
}

async fn list_users(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<UserRow>>> {
    user.require(Permission::ManageUsers)?;
    Ok(Json(db::list_users(&st.db).await?))
}

async fn create_user(
    State(st): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateUserRequest>,
) -> ApiResult<Json<Value>> {
    user.require(Permission::ManageUsers)?;
    validate_password(&req.password)?;

    let hash = auth::hash_password(&req.password)?;
    let id = db::create_user(&st.db, req.username.trim(), &hash, req.role)
        .await
        .map_err(|_| ApiError::conflict("Użytkownik o tej nazwie już istnieje"))?;

    Ok(Json(json!({ "id": id })))
}

async fn update_user(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<StatusCode> {
    user.require(Permission::ManageUsers)?;

    let password_changed = req.password.is_some();
    let password_hash = match req.password {
        Some(password) => {
            validate_password(&password)?;
            Some(auth::hash_password(&password)?)
        }
        None => None,
    };
    if !db::update_user(&st.db, &id, req.role, password_hash).await? {
        return Err(ApiError::NotFound);
    }

    // Zmiana hasła kończy aktywne sesje. Zmiana roli działa od razu bez wylogowania (rola czytana z bazy).
    if password_changed {
        db::delete_user_sessions(&st.db, &id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_user(State(st): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    user.require(Permission::ManageUsers)?;
    if id == user.user_id {
        return Err(ApiError::bad_request("Nie można usunąć własnego konta"));
    }
    // Sesje usuwa `ON DELETE CASCADE`.
    if !db::delete_user(&st.db, &id).await? {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn validate_password(password: &str) -> ApiResult<()> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ApiError::bad_request(format!(
            "Hasło musi mieć co najmniej {MIN_PASSWORD_LENGTH} znaków"
        )));
    }
    Ok(())
}

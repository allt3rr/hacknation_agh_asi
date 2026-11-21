use super::{ApiError, ApiResult};
use crate::auth::{AuthUser, Permission};
use crate::db;
use crate::fingerprint::SignatureSet;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/signatures", get(list_signatures).post(add_signature))
        .route("/signatures/:id", axum::routing::put(update_signature).delete(delete_signature))
}

#[derive(Deserialize)]
struct AddSignatureRequest {
    yaml: String,
}

#[derive(Deserialize)]
struct UpdateSignatureRequest {
    #[serde(default)]
    yaml: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

/// Sprawdza YAML i wyrażenia regularne, zwraca nazwę (id pierwszej sygnatury).
fn validate_yaml(yaml: &str) -> ApiResult<String> {
    let parsed = SignatureSet::parse_yaml(yaml).map_err(ApiError::bad_request)?;
    let name = match parsed.first() {
        Some(signature) => signature.id.clone(),
        None => return Err(ApiError::bad_request("Plik nie zawiera żadnej sygnatury")),
    };
    SignatureSet::new(parsed).map_err(ApiError::bad_request)?;
    Ok(name)
}

/// `active` to wszystkie załadowane sygnatury, `custom` to te dodane przez użytkowników.
async fn list_signatures(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require(Permission::Read)?;
    let active = st.signatures.read().await.signatures().to_vec();
    let custom = db::list_signatures(&st.db).await?;
    Ok(Json(json!({ "active": active, "custom": custom })))
}

async fn add_signature(
    State(st): State<AppState>,
    user: AuthUser,
    Json(req): Json<AddSignatureRequest>,
) -> ApiResult<Json<Value>> {
    user.require(Permission::ManageSignatures)?;

    let name = validate_yaml(&req.yaml)?;

    let id = db::insert_signature(&st.db, &name, &req.yaml, &user.username)
        .await
        .map_err(|_| ApiError::conflict(format!("Sygnatura '{name}' już istnieje")))?;
    let active_count = st.reload_signatures().await?;

    Ok(Json(json!({ "id": id, "active_signatures": active_count })))
}

async fn update_signature(
    State(st): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateSignatureRequest>,
) -> ApiResult<Json<Value>> {
    user.require(Permission::ManageSignatures)?;

    let name = req.yaml.as_deref().map(validate_yaml).transpose()?;
    let name_yaml = name.as_deref().zip(req.yaml.as_deref());
    let updated = db::update_signature(&st.db, &id, name_yaml, req.enabled)
        .await
        .map_err(|_| ApiError::conflict(format!("Sygnatura '{}' już istnieje", name.as_deref().unwrap_or_default())))?;
    if !updated {
        return Err(ApiError::NotFound);
    }
    let active_count = st.reload_signatures().await?;
    Ok(Json(json!({ "id": id, "active_signatures": active_count })))
}

async fn delete_signature(State(st): State<AppState>, user: AuthUser, Path(id): Path<String>) -> ApiResult<StatusCode> {
    user.require(Permission::ManageSignatures)?;
    if !db::delete_signature(&st.db, &id).await? {
        return Err(ApiError::NotFound);
    }
    st.reload_signatures().await?;
    Ok(StatusCode::NO_CONTENT)
}

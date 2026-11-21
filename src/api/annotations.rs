use super::ApiResult;
use crate::auth::{AuthUser, Permission};
use crate::db::{self, Annotation};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};

pub fn routes() -> Router<AppState> {
    Router::new().route("/annotations", get(list_annotations).put(save_annotation))
}

async fn list_annotations(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Vec<Annotation>>> {
    user.require(Permission::Read)?;
    Ok(Json(db::list_annotations(&st.db, &st.crypto).await?))
}

async fn save_annotation(
    State(st): State<AppState>,
    user: AuthUser,
    Json(annotation): Json<Annotation>,
) -> ApiResult<StatusCode> {
    user.require(Permission::Modify)?;
    db::upsert_annotation(&st.db, &st.crypto, &annotation, &user.username).await?;
    Ok(StatusCode::NO_CONTENT)
}

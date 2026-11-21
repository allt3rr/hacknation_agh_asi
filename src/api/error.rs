use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::fmt::Display;

pub type ApiResult<T> = Result<T, ApiError>;

pub enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest(String),
    Conflict(String),
    Internal(anyhow::Error),
}

impl ApiError {
    pub fn bad_request(message: impl Display) -> Self {
        ApiError::BadRequest(message.to_string())
    }

    pub fn conflict(message: impl Display) -> Self {
        ApiError::Conflict(message.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Wymagane zalogowanie".to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "Brak uprawnień dla tej roli".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Nie znaleziono".to_string()),
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            ApiError::Conflict(message) => (StatusCode::CONFLICT, message),
            ApiError::Internal(error) => {
                tracing::error!(error = ?error, "błąd wewnętrzny");
                (StatusCode::INTERNAL_SERVER_ERROR, "Błąd wewnętrzny serwera".to_string())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// Pozwala używać `?` na błędach anyhow/sqlx w handlerach.
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(error: E) -> Self {
        ApiError::Internal(error.into())
    }
}

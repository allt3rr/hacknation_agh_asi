use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub enum ApiError {
    /// Brak lub nieważna sesja.
    Unauthorized,
    /// Błędny login lub hasło: jedna treść dla wszystkich przyczyn.
    InvalidCredentials,
    Forbidden,
    NotFound,
    BadRequest(String),
    Conflict(String),
    BadGateway(String),
    TooManyRequests,
    Unavailable,
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message): (StatusCode, std::borrow::Cow<str>) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Wymagane zalogowanie".into()),
            ApiError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "Nieprawidłowy login lub hasło".into(),
            ),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "Brak uprawnień dla tej roli".into()),
            ApiError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "Zbyt wiele prób logowania, spróbuj później".into(),
            ),
            ApiError::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Baza danych niedostępna".into(),
            ),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Nie znaleziono".into()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.into()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m.into()),
            ApiError::BadGateway(m) => (StatusCode::BAD_GATEWAY, m.into()),
            ApiError::Internal(error) => {
                tracing::error!(error = ?error, "błąd wewnętrzny");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Błąd wewnętrzny serwera".into(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(error: E) -> Self {
        ApiError::Internal(error.into())
    }
}

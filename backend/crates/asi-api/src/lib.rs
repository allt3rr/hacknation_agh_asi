//! API HTTP ASI. `/api/health` bez logowania, reszta pod `/api/v1`.
//! Uprawnienia egzekwuje wyłącznie backend (`AuthUser::require`).

mod auth;
pub mod defectdojo;
mod error;
mod login_guard;
mod manage;
mod results;
mod routes;
pub mod scans;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_manage;
#[cfg(test)]
mod tests_results;
#[cfg(test)]
mod tests_scans;

pub use auth::{AuthUser, SESSION_COOKIE};
pub use error::{ApiError, ApiResult};

use asi_crypto::FieldCrypto;
use asi_db::Db;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, patch, post, put};
use axum::Router;
use login_guard::LoginGuard;
use std::sync::Arc;

/// Import plików celów i wyników.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub session_ttl_hours: i64,
    pub cookie_secure: bool,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub cfg: Arc<ApiConfig>,
    pub crypto: Arc<FieldCrypto>,
    pub scans: Arc<scans::ScanService>,
    pub defectdojo: Option<Arc<defectdojo::DefectDojo>>,
    login: Arc<LoginGuard>,
}

impl AppState {
    pub fn new(db: Db, cfg: ApiConfig, crypto: FieldCrypto) -> anyhow::Result<Self> {
        Ok(Self {
            db,
            cfg: Arc::new(cfg),
            crypto: Arc::new(crypto),
            scans: Arc::new(scans::ScanService::default()),
            defectdojo: None,
            login: Arc::new(LoginGuard::new()?),
        })
    }
}

impl AppState {
    pub fn with_defectdojo(mut self, dd: Option<defectdojo::DefectDojo>) -> Self {
        self.defectdojo = dd.map(Arc::new);
        self
    }

    pub fn with_scans(mut self, scans: scans::ScanService) -> Self {
        self.scans = Arc::new(scans);
        self
    }
}

/// Interfejs (zbudowany `frontend/dist`) z tego samego originu co API. Ścieżki spoza `/api`
/// trafiają do aplikacji React (routing po stronie klienta → `index.html`).
pub fn with_static(router: Router, dir: &std::path::Path) -> Router {
    let spa = tower_http::services::ServeDir::new(dir)
        .fallback(tower_http::services::ServeFile::new(dir.join("index.html")));
    router.fallback_service(spa)
}

pub fn router(state: AppState) -> Router {
    let v1 = Router::new()
        .route("/auth/login", post(routes::login))
        .route("/auth/logout", post(routes::logout))
        .route("/auth/config", get(routes::auth_config))
        .route("/me", get(routes::me))
        .route("/admin/ping", get(routes::admin_ping))
        .route(
            "/targets",
            get(manage::list_targets).post(manage::add_targets),
        )
        .route("/targets/import", post(manage::import_targets))
        .route(
            "/targets/{id}",
            patch(manage::update_target).delete(manage::delete_target),
        )
        .route(
            "/admin/users",
            get(manage::list_users).post(manage::create_user),
        )
        .route(
            "/admin/users/{id}",
            patch(manage::update_user).delete(manage::delete_user),
        )
        .route("/admin/audit", get(manage::list_audit))
        .route("/runs", get(scans::list_runs).post(scans::post_run))
        .route("/runs/{id}", get(scans::get_run))
        .route("/runs/{id}/cancel", post(scans::cancel_run))
        .route("/runs/{id}/observations", get(results::observations))
        .route("/runs/{id}/changes", get(results::changes))
        .route("/runs/{id}/export", get(results::export_run))
        .route("/runs/{id}/defectdojo", post(defectdojo::export))
        .route("/observations/{id}/secrets", get(results::secrets))
        .route("/dashboard", get(results::dashboard))
        .route("/results/import", post(results::import_results))
        .route(
            "/overrides",
            get(results::list_overrides)
                .put(results::put_override)
                .delete(results::delete_override),
        )
        .route(
            "/signatures",
            get(results::list_signatures).post(results::create_signatures),
        )
        .route(
            "/signatures/{slug}",
            put(results::update_signature).delete(results::delete_signature),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    Router::new()
        .route("/api/health", get(routes::health))
        .nest("/api/v1", v1)
        .with_state(state)
}

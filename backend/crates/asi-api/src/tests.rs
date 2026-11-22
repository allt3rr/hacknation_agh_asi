//! Testy API na prawdziwym PostgreSQL (`#[sqlx::test]` tworzy osobną bazę na test; wymaga DATABASE_URL).

use crate::{router, ApiConfig, AppState};
use asi_core::{password, rbac};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::time::Duration;
use tower::ServiceExt;

pub(crate) const PASSWORD: &str = "dobre-haslo-123";

pub(crate) fn demo_crypto() -> asi_crypto::FieldCrypto {
    asi_crypto::FieldCrypto::from_base64(&asi_crypto::FieldCrypto::generate_key()).unwrap()
}

pub(crate) fn state(db: &PgPool) -> AppState {
    AppState::new(
        db.clone(),
        ApiConfig {
            session_ttl_hours: 12,
            cookie_secure: false,
        },
        demo_crypto(),
    )
    .unwrap()
}

pub(crate) async fn prepared(db: &PgPool) -> AppState {
    asi_db::prepare(db, Some("fixture-password")).await.unwrap();
    state(db)
}

pub(crate) async fn add_user(db: &PgPool, name: &str, role: &str) -> uuid::Uuid {
    asi_db::users::create_user(db, name, &password::hash_password(PASSWORD).unwrap(), role)
        .await
        .unwrap()
}

pub(crate) async fn call(
    st: &AppState,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> Response {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    let body = match body {
        Some(json) => {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    router(st.clone())
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap()
}

pub(crate) async fn login_as(st: &AppState, name: &str, password: &str) -> Response {
    call(
        st,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(json!({ "username": name, "password": password })),
    )
    .await
}

pub(crate) fn set_cookie(res: &Response) -> Option<String> {
    res.headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string())
}

pub(crate) fn cookie_pair(res: &Response) -> String {
    set_cookie(res)
        .expect("Set-Cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

pub(crate) async fn body(res: Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn health_ok_then_503_when_db_down(db: PgPool) {
    let st = prepared(&db).await;
    assert_eq!(
        call(&st, "GET", "/api/health", None, None).await.status(),
        StatusCode::OK
    );
    db.close().await;
    assert_eq!(
        call(&st, "GET", "/api/health", None, None).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn demo_admin_logs_in_with_cookie(db: PgPool) {
    let st = prepared(&db).await;
    let res = login_as(&st, "admin", "fixture-password").await;
    assert_eq!(res.status(), StatusCode::OK);
    let cookie = set_cookie(&res).unwrap();
    for attr in [
        "asi_session=",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=43200",
    ] {
        assert!(cookie.contains(attr), "brak {attr} w {cookie}");
    }
    let pair = cookie_pair(&res);
    let profile = body(res).await;
    assert_eq!(profile["username"], "admin");
    assert_eq!(profile["roles"], json!(["admin"]));
    assert!(profile["permissions"]
        .as_array()
        .unwrap()
        .contains(&json!("admin.users")));

    let me = call(&st, "GET", "/api/v1/me", Some(&pair), None).await;
    assert_eq!(me.status(), StatusCode::OK);

    // token nie występuje jawnie w bazie
    let token = pair.trim_start_matches("asi_session=");
    let leaked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sessions WHERE encode(id_hash, 'escape') = $1 OR user_agent = $1",
    )
    .bind(token)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(leaked, 0);
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn secure_cookie_when_configured(db: PgPool) {
    asi_db::prepare(&db, Some("fixture-password"))
        .await
        .unwrap();
    let st = AppState::new(
        db.clone(),
        ApiConfig {
            session_ttl_hours: 12,
            cookie_secure: true,
        },
        demo_crypto(),
    )
    .unwrap();
    assert!(
        set_cookie(&login_as(&st, "admin", "fixture-password").await)
            .unwrap()
            .contains("Secure")
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn wrong_password_unknown_user_and_disabled_account(db: PgPool) {
    let st = prepared(&db).await;
    let wrong = login_as(&st, "admin", "zle").await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert!(set_cookie(&wrong).is_none());
    let wrong_body = body(wrong).await;

    let unknown = login_as(&st, "nikt", "zle").await;
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body(unknown).await, wrong_body);

    add_user(&db, "wyl", rbac::VIEWER).await;
    sqlx::query("UPDATE users SET disabled = true WHERE username = 'wyl'")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        login_as(&st, "wyl", PASSWORD).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let audit: Vec<(String, Value)> =
        sqlx::query_as("SELECT action, details FROM audit_log WHERE action = 'auth.login_failed'")
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(audit.len(), 3);
    assert!(audit.iter().all(|(_, d)| !d.to_string().contains("zle")));
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn sixth_attempt_is_blocked_even_with_correct_password(db: PgPool) {
    let st = prepared(&db).await;
    for _ in 0..crate::login_guard::MAX_FAILURES {
        assert_eq!(
            login_as(&st, "admin", "zle").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let res = login_as(&st, "admin", "fixture-password").await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(set_cookie(&res).is_none());
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn health_answers_during_parallel_logins(db: PgPool) {
    let st = prepared(&db).await;
    let logins: Vec<_> = (0..20)
        .map(|i| {
            let st = st.clone();
            tokio::spawn(async move { login_as(&st, &format!("u{i}"), "x").await })
        })
        .collect();
    let health = tokio::time::timeout(
        Duration::from_secs(2),
        call(&st, "GET", "/api/health", None, None),
    )
    .await;
    assert_eq!(
        health.expect("health zablokowany przez logowania").status(),
        StatusCode::OK
    );
    for l in logins {
        assert!(matches!(
            l.await.unwrap().status(),
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
        ));
    }
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn session_survives_restart_expires_and_follows_credential_version(db: PgPool) {
    let st = prepared(&db).await;
    let pair = cookie_pair(&login_as(&st, "admin", "fixture-password").await);

    let restarted = state(&db);
    assert_eq!(
        call(&restarted, "GET", "/api/v1/me", Some(&pair), None)
            .await
            .status(),
        StatusCode::OK
    );

    sqlx::query("UPDATE users SET credential_version = credential_version + 1")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        call(&restarted, "GET", "/api/v1/me", Some(&pair), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let pair = cookie_pair(&login_as(&st, "admin", "fixture-password").await);
    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        call(&st, "GET", "/api/v1/me", Some(&pair), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn logout_always_clears_cookie(db: PgPool) {
    let st = prepared(&db).await;
    let pair = cookie_pair(&login_as(&st, "admin", "fixture-password").await);

    let res = call(&st, "POST", "/api/v1/auth/logout", Some(&pair), None).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(set_cookie(&res).unwrap().contains("Max-Age=0"));
    assert_eq!(
        call(&st, "GET", "/api/v1/me", Some(&pair), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    for cookie in [Some(pair.as_str()), None] {
        let res = call(&st, "POST", "/api/v1/auth/logout", cookie, None).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(set_cookie(&res).unwrap().contains("Max-Age=0"));
    }
    let logouts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'auth.logout'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(logouts, 1);
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn role_matrix_on_admin_ping(db: PgPool) {
    let st = prepared(&db).await;
    assert_eq!(
        call(&st, "GET", "/api/v1/admin/ping", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for role in rbac::BUILTIN_ROLES {
        let name = format!("u-{role}");
        add_user(&db, &name, role).await;
        let pair = cookie_pair(&login_as(&st, &name, PASSWORD).await);
        let expected = if *role == rbac::ADMIN {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(
            call(&st, "GET", "/api/v1/admin/ping", Some(&pair), None)
                .await
                .status(),
            expected,
            "{role}"
        );
    }
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn auth_config_reports_ttl(db: PgPool) {
    let st = AppState::new(
        db.clone(),
        ApiConfig {
            session_ttl_hours: 8,
            cookie_secure: false,
        },
        demo_crypto(),
    )
    .unwrap();
    let res = call(&st, "GET", "/api/v1/auth/config", None, None).await;
    assert_eq!(body(res).await, json!({ "session_ttl_hours": 8 }));
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn static_frontend_with_spa_fallback(db: PgPool) {
    let dir = std::env::temp_dir().join(format!("asi-static-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<title>ASI</title>").unwrap();
    let app = crate::with_static(router(prepared(&db).await), &dir);
    let get = |uri: &str| Request::builder().uri(uri).body(Body::empty()).unwrap();

    for uri in ["/", "/runs/123"] {
        let res = app.clone().oneshot(get(uri)).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{uri}");
        let html = axum::body::to_bytes(res.into_body(), 1 << 16)
            .await
            .unwrap();
        assert_eq!(&html[..], b"<title>ASI</title>");
    }
    let res = app.clone().oneshot(get("/api/v1/me")).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    std::fs::remove_dir_all(dir).ok();
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn login_rejects_oversized_payload(db: PgPool) {
    let st = prepared(&db).await;
    let res = login_as(&st, "admin", &"a".repeat(20 * 1024)).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

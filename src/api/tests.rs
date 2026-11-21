//! Testy API przez router (bez sieci): sesja w cookie, RBAC, wylogowanie.

use crate::auth::{self, Role};
use crate::config::Config;
use crate::db::{self, Db};
use crate::state::AppState;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use tower::ServiceExt;

const PASSWORD: &str = "dobre-haslo-123";

async fn setup() -> (Db, AppState) {
    let db = db::connect_memory().await.unwrap();
    let st = AppState::for_tests(db.clone(), |_| {});
    (db, st)
}

async fn add_user(db: &Db, name: &str, role: Role) -> String {
    db::create_user(db, name, &auth::hash_password(PASSWORD).unwrap(), role)
        .await
        .unwrap()
}

async fn call(
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
    crate::api::router(st.clone())
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap()
}

fn set_cookie(res: &Response) -> Option<String> {
    res.headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string())
}

async fn json_body(res: Response) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Loguje i zwraca wartość nagłówka `Cookie` do kolejnych żądań.
async fn login(st: &AppState, name: &str) -> String {
    let res = call(
        st,
        "POST",
        "/api/login",
        None,
        Some(json!({ "username": name, "password": PASSWORD })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let header = set_cookie(&res).expect("Set-Cookie");
    header.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn health_without_env_or_files() {
    let (_db, st) = setup().await;
    assert_eq!(
        call(&st, "GET", "/api/health", None, None).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn login_sets_session_cookie_without_token_in_body() {
    let (db, st) = setup().await;
    add_user(&db, "admin", Role::Admin).await;

    let res = call(
        &st,
        "POST",
        "/api/login",
        None,
        Some(json!({ "username": "admin", "password": PASSWORD })),
    )
    .await;
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
    assert!(!cookie.contains("Secure"));

    let body = json_body(res).await;
    assert_eq!(body, json!({ "username": "admin", "role": "admin" }));
}

#[tokio::test]
async fn wrong_password_gives_401_without_cookie() {
    let (db, st) = setup().await;
    add_user(&db, "admin", Role::Admin).await;

    let res = call(
        &st,
        "POST",
        "/api/login",
        None,
        Some(json!({ "username": "admin", "password": "zle" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(set_cookie(&res).is_none());
}

#[tokio::test]
async fn secure_attribute_when_configured() {
    let db = db::connect_memory().await.unwrap();
    let st = AppState::for_tests(db.clone(), |cfg: &mut Config| {
        cfg.server.cookie_secure = true
    });
    add_user(&db, "admin", Role::Admin).await;

    let res = call(
        &st,
        "POST",
        "/api/login",
        None,
        Some(json!({ "username": "admin", "password": PASSWORD })),
    )
    .await;
    assert!(set_cookie(&res).unwrap().contains("Secure"));
}

#[tokio::test]
async fn only_cookie_authenticates_and_token_is_not_stored() {
    let (db, st) = setup().await;
    add_user(&db, "admin", Role::Admin).await;
    let cookie = login(&st, "admin").await;
    let token = cookie.trim_start_matches("asi_session=");

    assert_eq!(
        call(&st, "GET", "/api/me", Some(&cookie), None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        call(&st, "GET", "/api/me", None, None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    let bearer = Request::builder()
        .uri("/api/me")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = crate::api::router(st.clone())
        .oneshot(bearer)
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let rows: Vec<(String, String)> = sqlx::query_as("SELECT id_hash, user_id FROM sessions")
        .fetch_all(&db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows
        .iter()
        .all(|(hash, user)| hash != token && user != token));
}

#[tokio::test]
async fn session_survives_restart_and_expires() {
    let (db, st) = setup().await;
    add_user(&db, "admin", Role::Admin).await;
    let cookie = login(&st, "admin").await;

    // "Restart": nowy stan aplikacji na tej samej bazie, bez niczego w pamięci.
    let restarted = AppState::for_tests(db.clone(), |_| {});
    assert_eq!(
        call(&restarted, "GET", "/api/me", Some(&cookie), None)
            .await
            .status(),
        StatusCode::OK
    );

    sqlx::query("UPDATE sessions SET expires_at = 0")
        .execute(&db)
        .await
        .unwrap();
    assert_eq!(
        call(&restarted, "GET", "/api/me", Some(&cookie), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_clears_cookie_and_invalidates_session() {
    let (db, st) = setup().await;
    add_user(&db, "admin", Role::Admin).await;
    let cookie = login(&st, "admin").await;

    let res = call(&st, "POST", "/api/logout", Some(&cookie), None).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let cleared = set_cookie(&res).unwrap();
    assert!(
        cleared.contains("asi_session=") && cleared.contains("Max-Age=0"),
        "{cleared}"
    );

    assert_eq!(
        call(&st, "GET", "/api/me", Some(&cookie), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_with_expired_or_missing_session_still_clears_cookie() {
    let (db, st) = setup().await;
    add_user(&db, "admin", Role::Admin).await;
    let cookie = login(&st, "admin").await;
    sqlx::query("UPDATE sessions SET expires_at = 0")
        .execute(&db)
        .await
        .unwrap();

    for cookie in [Some(cookie.as_str()), None] {
        let res = call(&st, "POST", "/api/logout", cookie, None).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        assert!(set_cookie(&res).unwrap().contains("Max-Age=0"));
    }
}

#[tokio::test]
async fn viewer_reads_but_cannot_manage_users() {
    let (db, st) = setup().await;
    add_user(&db, "ola", Role::Viewer).await;
    let cookie = login(&st, "ola").await;

    assert_eq!(
        call(&st, "GET", "/api/dashboard", Some(&cookie), None)
            .await
            .status(),
        StatusCode::OK
    );
    let new_user = json!({ "username": "x", "password": PASSWORD, "role": "viewer" });
    let res = call(&st, "POST", "/api/users", Some(&cookie), Some(new_user)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn role_change_applies_without_relogin_and_deletion_ends_session() {
    let (db, st) = setup().await;
    add_user(&db, "admin", Role::Admin).await;
    let editor_id = add_user(&db, "edek", Role::Editor).await;
    let admin = login(&st, "admin").await;
    let editor = login(&st, "edek").await;
    let add_target = json!({ "text": "10.0.0.1" });

    let res = call(
        &st,
        "POST",
        "/api/targets",
        Some(&editor),
        Some(add_target.clone()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);

    let path = format!("/api/users/{editor_id}");
    let res = call(
        &st,
        "PUT",
        &path,
        Some(&admin),
        Some(json!({ "role": "viewer" })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = call(&st, "POST", "/api/targets", Some(&editor), Some(add_target)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = call(&st, "DELETE", &path, Some(&admin), None).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        call(&st, "GET", "/api/me", Some(&editor), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

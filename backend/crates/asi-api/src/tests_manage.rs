//! Testy API celów, kont i audytu (zmiana `cele-i-konta`).

use crate::tests::{add_user, body, call, cookie_pair, login_as, prepared, PASSWORD};
use crate::{router, AppState};
use asi_core::rbac;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

async fn logged(st: &AppState, db: &PgPool, name: &str, role: &str) -> String {
    add_user(db, name, role).await;
    cookie_pair(&login_as(st, name, PASSWORD).await)
}

async fn user_id(db: &PgPool, name: &str) -> uuid::Uuid {
    sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(name)
        .fetch_one(db)
        .await
        .unwrap()
}

async fn import(st: &AppState, cookie: &str, query: &str, data: String) -> Response {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/targets/import?{query}"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "text/csv")
        .body(Body::from(data))
        .unwrap();
    router(st.clone()).oneshot(req).await.unwrap()
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn targets_manual_add_and_permission_matrix(db: PgPool) {
    let st = prepared(&db).await;
    let editor = logged(&st, &db, "ed", rbac::EDITOR).await;
    let analyst = logged(&st, &db, "an", rbac::ANALYST).await;
    let viewer = logged(&st, &db, "vi", rbac::VIEWER).await;

    let text = json!({ "text": "10.0.0.1, 10.0.0.0/24\nIntranet.AGH.edu.pl\nxx" });
    let res = call(
        &st,
        "POST",
        "/api/v1/targets",
        Some(&editor),
        Some(text.clone()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let summary = body(res).await;
    assert_eq!(summary["accepted"], 3);
    assert_eq!(summary["rejected"][0]["value"], "xx");

    let list = body(call(&st, "GET", "/api/v1/targets", Some(&viewer), None).await).await;
    let domain = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["kind"] == "domain")
        .unwrap();
    assert_eq!(domain["value"], "intranet.agh.edu.pl");
    let id = domain["id"].as_str().unwrap().to_string();
    let path = format!("/api/v1/targets/{id}");

    let denied = call(&st, "POST", "/api/v1/targets", Some(&viewer), Some(text)).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied = call(&st, "DELETE", &path, Some(&analyst), None).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let patch = json!({ "note": "serwer księgowości", "tags": ["dmz"] });
    let ok = call(&st, "PATCH", &path, Some(&analyst), Some(patch)).await;
    assert_eq!(ok.status(), StatusCode::OK);
    let anon = call(&st, "GET", "/api/v1/targets", None, None).await;
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);

    let list = body(call(&st, "GET", "/api/v1/targets", Some(&viewer), None).await).await;
    let t = list
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id.as_str())
        .unwrap();
    assert_eq!(t["note"], "serwer księgowości");
    let raw: Vec<u8> = sqlx::query_scalar("SELECT note_enc FROM targets WHERE id = $1::uuid")
        .bind(&id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("księgowości"));

    let res = call(&st, "DELETE", &path, Some(&editor), None).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = call(&st, "DELETE", &path, Some(&editor), None).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn import_organizer_file_and_reimport(db: PgPool) {
    use std::fmt::Write as _;

    let st = prepared(&db).await;
    let editor = logged(&st, &db, "ed", rbac::EDITOR).await;
    let analyst = logged(&st, &db, "an", rbac::ANALYST).await;
    let mut data = String::from("record_id,ip_address,subnet_cidr,hostname,port,network_zone\n");
    for row in 0..10_000 {
        let target = row % 2_800;
        let subnet = 10 + target / 254;
        let host = 1 + target % 254;
        let port = 80 + row / 2_800;
        writeln!(
            data,
            "{row},10.10.{subnet}.{host},10.10.{subnet}.0/24,,{port},PROD"
        )
        .unwrap();
    }
    let count = |db: PgPool| async move {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM targets")
            .fetch_one(&db)
            .await
            .unwrap()
    };
    let n = |v: &serde_json::Value, k: &str| v[k].as_u64().unwrap();

    assert_eq!(count(db.clone()).await, 0);
    let real = body(import(&st, &editor, "format=csv", data.clone()).await).await;
    assert_eq!(
        (
            n(&real, "rows"),
            n(&real, "accepted"),
            n(&real, "duplicates")
        ),
        (10000, 2800, 7200)
    );
    assert!(real["rejected"].as_array().unwrap().is_empty());
    assert_eq!(count(db.clone()).await, 2800);

    let tags: Vec<String> =
        sqlx::query_scalar("SELECT tags FROM targets WHERE value = '10.10.10.3'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(tags.contains(&"subnet:10.10.10.0/24".to_string()));
    assert!(tags.contains(&"zone:PROD".to_string()));

    let id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM targets WHERE value = '10.10.10.3'")
        .fetch_one(&db)
        .await
        .unwrap();
    let patch = json!({ "tags": ["analityk"] });
    let path = format!("/api/v1/targets/{id}");
    call(&st, "PATCH", &path, Some(&analyst), Some(patch)).await;
    let again = body(import(&st, &editor, "format=csv", data).await).await;
    assert_eq!((n(&again, "accepted"), n(&again, "duplicates")), (0, 10000));
    let tags: Vec<String> = sqlx::query_scalar("SELECT tags FROM targets WHERE id = $1")
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(tags, vec!["analityk"]);

    let bad = import(&st, &editor, "format=csv", "foo\n1\n".into()).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn user_admin_flow_and_audit(db: PgPool) {
    let st = prepared(&db).await;
    let admin = cookie_pair(&login_as(&st, "admin", "fixture-password").await);
    let editor = logged(&st, &db, "edek", rbac::EDITOR).await;
    let users = "/api/v1/admin/users";

    let res = call(&st, "GET", users, Some(&editor), None).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let new = json!({ "username": "ola", "password": "haslo-ola-12", "role": "viewer" });
    let res = call(&st, "POST", users, Some(&admin), Some(new.clone())).await;
    assert_eq!(res.status(), StatusCode::OK);
    let ola_path = format!("{users}/{}", body(res).await["id"].as_str().unwrap());
    let res = call(&st, "POST", users, Some(&admin), Some(new)).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let bad_role = json!({ "username": "x", "password": "haslo-ola-12", "role": "root" });
    let res = call(&st, "POST", users, Some(&admin), Some(bad_role)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let ola = cookie_pair(&login_as(&st, "ola", "haslo-ola-12").await);
    let short = json!({ "password": "krotkie" });
    let res = call(&st, "PATCH", &ola_path, Some(&admin), Some(short)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = call(&st, "GET", "/api/v1/me", Some(&ola), None).await;
    assert_eq!(res.status(), StatusCode::OK);

    let reset = json!({ "password": "nowe-haslo-ola" });
    let res = call(&st, "PATCH", &ola_path, Some(&admin), Some(reset)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = call(&st, "GET", "/api/v1/me", Some(&ola), None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = login_as(&st, "ola", "haslo-ola-12").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = login_as(&st, "ola", "nowe-haslo-ola").await;
    assert_eq!(res.status(), StatusCode::OK);

    // zmiana roli działa bez wylogowania
    let add = json!({ "text": "10.0.0.9" });
    let res = call(
        &st,
        "POST",
        "/api/v1/targets",
        Some(&editor),
        Some(add.clone()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let demote = json!({ "role": "viewer" });
    let edek_path = format!("{users}/{}", user_id(&db, "edek").await);
    call(&st, "PATCH", &edek_path, Some(&admin), Some(demote.clone())).await;
    let res = call(&st, "POST", "/api/v1/targets", Some(&editor), Some(add)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // ostatni aktywny admin
    let admin_path = format!("{users}/{}", user_id(&db, "admin").await);
    let res = call(&st, "PATCH", &admin_path, Some(&admin), Some(demote)).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let res = call(&st, "DELETE", &admin_path, Some(&admin), None).await;
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let res = call(&st, "DELETE", &ola_path, Some(&admin), None).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // dziennik audytu
    let audit = body(
        call(
            &st,
            "GET",
            "/api/v1/admin/audit?limit=5",
            Some(&admin),
            None,
        )
        .await,
    )
    .await;
    let rows = audit.as_array().unwrap();
    assert_eq!(rows.len(), 5);
    assert!(rows
        .windows(2)
        .all(|w| w[0]["id"].as_i64() > w[1]["id"].as_i64()));
    let all = call(
        &st,
        "GET",
        "/api/v1/admin/audit?limit=500",
        Some(&admin),
        None,
    )
    .await;
    let all = body(all).await.to_string();
    for action in ["user.update", "user.create", "user.delete", "target.create"] {
        assert!(all.contains(action), "brak {action}");
    }
    assert!(!all.contains("nowe-haslo-ola") && !all.contains("$argon2"));

    let analyst = logged(&st, &db, "an", rbac::ANALYST).await;
    let res = call(&st, "GET", "/api/v1/admin/audit", Some(&analyst), None).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrator = "asi_db::MIGRATOR")]
async fn audit_failure_rolls_back_user_creation(db: PgPool) {
    let st = prepared(&db).await;
    let admin = cookie_pair(&login_as(&st, "admin", "fixture-password").await);
    sqlx::query("ALTER TABLE audit_log ADD CHECK (action <> 'user.create')")
        .execute(&db)
        .await
        .unwrap();
    let input = json!({"username":"rollback", "password":"fixture-password", "role":"viewer"});
    let res = call(
        &st,
        "POST",
        "/api/v1/admin/users",
        Some(&admin),
        Some(input),
    )
    .await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(asi_db::users::find_credentials(&db, "rollback")
        .await
        .unwrap()
        .is_none());
}

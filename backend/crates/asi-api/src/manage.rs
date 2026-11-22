//! Cele, konta i dziennik audytu.

use crate::auth::{AuthUser, ClientIp};
use crate::{ApiError, ApiResult, AppState};
use asi_core::targets::{self, ParseReport, Rejected, Target};
use asi_core::{password, rbac};
use asi_db::audit::{self, AuditRow, Entry};
use asi_db::targets::{TargetPatch, TargetView};
use asi_db::users::{Outcome, UserSummary, UserUpdate};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

pub const MIN_PASSWORD_LENGTH: usize = 10;

async fn record<'c>(
    db: impl sqlx::PgExecutor<'c>,
    user: &AuthUser,
    ip: &ClientIp,
    action: &str,
    entity: &str,
    id: Option<String>,
    details: Value,
) -> ApiResult<()> {
    let entry = Entry {
        user_id: Some(user.0.id),
        username: Some(&user.0.username),
        action,
        entity: Some(entity),
        entity_id: id,
        ip: ip.0.map(|i| i.to_string()),
        details,
    };
    Ok(audit::record(db, entry).await?)
}

// --- Cele ---------------------------------------------------------------------

#[derive(Serialize)]
pub struct ImportSummary {
    rows: usize,
    accepted: u64,
    duplicates: usize,
    rejected: Vec<Rejected>,
}

#[derive(Deserialize)]
pub struct TargetInput {
    value: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
pub struct AddTargets {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    targets: Vec<TargetInput>,
}

#[derive(Deserialize)]
pub struct ImportQuery {
    #[serde(default = "default_format")]
    format: String,
}

fn default_format() -> String {
    "csv".into()
}

pub async fn list_targets(
    State(st): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Vec<TargetView>>> {
    user.require(rbac::READ)?;
    Ok(Json(
        asi_db::targets::list_targets(&st.db, &st.crypto).await?,
    ))
}

/// Zapisuje cele z raportu. Cele już istniejące w bazie to duplikaty.
async fn save(
    st: &AppState,
    user: &AuthUser,
    report: ParseReport,
    source: &str,
) -> ApiResult<ImportSummary> {
    let new = asi_db::targets::insert_targets(
        &st.db,
        &st.crypto,
        &report.targets,
        source,
        Some(user.0.id),
    )
    .await?;
    Ok(ImportSummary {
        rows: report.rows,
        accepted: new,
        duplicates: report.duplicates + (report.targets.len() - new as usize),
        rejected: report.rejected,
    })
}

pub async fn add_targets(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Json(req): Json<AddTargets>,
) -> ApiResult<Json<ImportSummary>> {
    user.require(rbac::TARGETS_CREATE)?;
    let mut report = req
        .text
        .as_deref()
        .map(targets::parse_text)
        .unwrap_or_default();
    let mut seen: std::collections::HashSet<(targets::TargetKind, String)> = report
        .targets
        .iter()
        .map(|t| (t.kind, t.value.clone()))
        .collect();
    for item in req.targets {
        report.rows += 1;
        match targets::classify(&item.value) {
            Some(t) if !seen.insert((t.kind, t.value.clone())) => report.duplicates += 1,
            Some(t) => report.targets.push(Target {
                tags: item.tags,
                note: item.note,
                ..t
            }),
            None => report.rejected.push(Rejected {
                row: report.rows,
                value: item.value,
            }),
        }
    }
    let summary = save(&st, &user, report, "manual").await?;
    record(
        &st.db,
        &user,
        &ip,
        "target.create",
        "target",
        None,
        json!({ "accepted": summary.accepted }),
    )
    .await?;
    Ok(Json(summary))
}

pub async fn import_targets(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Query(q): Query<ImportQuery>,
    body: String,
) -> ApiResult<Json<ImportSummary>> {
    user.require(rbac::TARGETS_CREATE)?;
    let report = targets::parse_by_format(&q.format, &body)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let source = match q.format.as_str() {
        "csv" => "csv",
        "json" => "json",
        _ => "import",
    };
    let summary = save(&st, &user, report, source).await?;
    let details = json!({ "format": source, "rows": summary.rows, "accepted": summary.accepted });
    record(&st.db, &user, &ip, "target.import", "target", None, details).await?;
    Ok(Json(summary))
}

pub async fn update_target(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(mut patch): Json<TargetPatch>,
) -> ApiResult<StatusCode> {
    user.require(rbac::TARGETS_UPDATE)?;
    if let Some(tags) = patch.tags.take() {
        patch.tags = Some(normalize_tags(tags).map_err(ApiError::BadRequest)?);
    }
    if !asi_db::targets::update_target(&st.db, &st.crypto, id, &patch).await? {
        return Err(ApiError::NotFound);
    }
    let fields: Vec<&str> = [
        patch.tags.is_some().then_some("tags"),
        patch.note.is_some().then_some("note"),
        patch.excluded.is_some().then_some("excluded"),
    ]
    .into_iter()
    .flatten()
    .collect();
    record(
        &st.db,
        &user,
        &ip,
        "target.update",
        "target",
        Some(id.to_string()),
        json!({ "fields": fields }),
    )
    .await?;
    Ok(StatusCode::OK)
}

const MAX_TAGS: usize = 32;
const MAX_TAG_LEN: usize = 64;

/// Tagi celu: przycięte, bez pustych i duplikatów (kolejność zachowana), z limitem liczby i długości.
fn normalize_tags(tags: Vec<String>) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for tag in tags {
        let tag = tag.trim();
        if tag.chars().count() > MAX_TAG_LEN {
            return Err(format!("Tag dłuższy niż {MAX_TAG_LEN} znaków"));
        }
        if !tag.is_empty() && !out.iter().any(|t| t == tag) {
            out.push(tag.to_string());
        }
    }
    if out.len() > MAX_TAGS {
        return Err(format!("Więcej niż {MAX_TAGS} tagów"));
    }
    Ok(out)
}

pub async fn delete_target(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    user.require(rbac::TARGETS_DELETE)?;
    if !asi_db::targets::delete_target(&st.db, id).await? {
        return Err(ApiError::NotFound);
    }
    record(
        &st.db,
        &user,
        &ip,
        "target.delete",
        "target",
        Some(id.to_string()),
        json!({}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Konta ----------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateUser {
    username: String,
    password: String,
    role: String,
}

#[derive(Deserialize)]
pub struct PatchUser {
    role: Option<String>,
    password: Option<String>,
    disabled: Option<bool>,
}

fn check_role(role: &str) -> ApiResult<()> {
    if rbac::BUILTIN_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!("Nieznana rola: {role}")))
    }
}

/// Jedna polityka haseł dla tworzenia konta i zmiany hasła; hash liczony poza wątkami obsługi żądań.
async fn hash_new_password(password: String) -> ApiResult<String> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "Hasło musi mieć co najmniej {MIN_PASSWORD_LENGTH} znaków"
        )));
    }
    Ok(tokio::task::spawn_blocking(move || password::hash_password(&password)).await??)
}

pub async fn list_users(
    State(st): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Vec<UserSummary>>> {
    user.require(rbac::ADMIN_USERS)?;
    Ok(Json(asi_db::users::list_users(&st.db).await?))
}

pub async fn create_user(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Json(req): Json<CreateUser>,
) -> ApiResult<Json<Value>> {
    user.require(rbac::ADMIN_USERS)?;
    let username = req.username.trim();
    if username.is_empty() {
        return Err(ApiError::BadRequest(
            "Nazwa użytkownika jest wymagana".into(),
        ));
    }
    check_role(&req.role)?;
    let hash = hash_new_password(req.password).await?;
    let mut tx = st.db.begin().await?;
    let id = match asi_db::users::create_user(&mut *tx, username, &hash, &req.role).await {
        Ok(id) => id,
        Err(e) if asi_db::users::is_unique_violation(&e) => {
            return Err(ApiError::Conflict(
                "Użytkownik o tej nazwie już istnieje".into(),
            ))
        }
        Err(e) => return Err(e.into()),
    };
    let details = json!({ "username": username, "role": req.role });
    record(
        &mut *tx,
        &user,
        &ip,
        "user.create",
        "user",
        Some(id.to_string()),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "id": id })))
}

fn outcome(result: Outcome) -> ApiResult<()> {
    match result {
        Outcome::Done => Ok(()),
        Outcome::NotFound => Err(ApiError::NotFound),
        Outcome::LastAdmin => Err(ApiError::Conflict(
            "Nie można odebrać uprawnień ostatniemu aktywnemu administratorowi".into(),
        )),
    }
}

pub async fn update_user(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchUser>,
) -> ApiResult<StatusCode> {
    user.require(rbac::ADMIN_USERS)?;
    if let Some(role) = &req.role {
        check_role(role)?;
    }
    let password_hash = match req.password {
        Some(p) => Some(hash_new_password(p).await?),
        None => None,
    };
    let fields: Vec<&str> = [
        req.role.is_some().then_some("role"),
        password_hash.is_some().then_some("password"),
        req.disabled.is_some().then_some("disabled"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let update = UserUpdate {
        role: req.role.clone(),
        password_hash,
        disabled: req.disabled,
    };
    let mut tx = st.db.begin().await?;
    outcome(asi_db::users::update_user(&mut *tx, id, &update).await?)?;
    let details = json!({ "fields": fields, "role": req.role, "disabled": req.disabled });
    record(
        &mut *tx,
        &user,
        &ip,
        "user.update",
        "user",
        Some(id.to_string()),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_user(
    State(st): State<AppState>,
    user: AuthUser,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    user.require(rbac::ADMIN_USERS)?;
    let mut tx = st.db.begin().await?;
    record(
        &mut *tx,
        &user,
        &ip,
        "user.delete",
        "user",
        Some(id.to_string()),
        json!({}),
    )
    .await?;
    outcome(asi_db::users::delete_user(&mut *tx, id).await?)?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Audyt ----------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
    before: Option<i64>,
}

pub async fn list_audit(
    State(st): State<AppState>,
    user: AuthUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditRow>>> {
    user.require(rbac::ADMIN_AUDIT)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    Ok(Json(audit::list(&st.db, limit, q.before).await?))
}

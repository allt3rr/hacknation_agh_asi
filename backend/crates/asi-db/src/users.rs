//! Użytkownicy, ich role i uprawnienia.

use anyhow::Result;
use asi_core::{password, rbac};
use sqlx::PgPool;
use uuid::Uuid;

/// Dane potrzebne do weryfikacji hasła przy logowaniu.
#[derive(Debug, sqlx::FromRow)]
pub struct Credentials {
    pub id: Uuid,
    pub password_hash: String,
    pub credential_version: i32,
    pub disabled: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Profile {
    pub id: Uuid,
    pub username: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
pub struct UserSummary {
    pub id: Uuid,
    pub username: String,
    pub disabled: bool,
    pub roles: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
}

/// Zmiana konta. `password_hash` i `disabled = Some(true)` zwiększają wersję poświadczeń.
#[derive(Debug, Default)]
pub struct UserUpdate {
    pub role: Option<String>,
    pub password_hash: Option<String>,
    pub disabled: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    NotFound,
    /// Zmiana zostawiłaby system bez aktywnego administratora.
    LastAdmin,
}

pub async fn list_users(db: &PgPool) -> Result<Vec<UserSummary>> {
    Ok(sqlx::query_as::<_, UserSummary>(
        "SELECT u.id, u.username, u.disabled, u.created_at,
                COALESCE(array_agg(r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
         FROM users u
         LEFT JOIN user_roles ur ON ur.user_id = u.id
         LEFT JOIN roles r ON r.id = ur.role_id
         GROUP BY u.id ORDER BY u.username",
    )
    .fetch_all(db)
    .await?)
}

/// Blokuje przypisania roli admin (serializuje równoczesne zmiany kont administratorów)
/// i sprawdza, czy po zmianie zostanie co najmniej jeden aktywny admin poza `user_id`.
async fn keeps_an_admin(tx: &mut sqlx::PgConnection, user_id: Uuid) -> Result<bool> {
    sqlx::query(
        "SELECT ur.user_id FROM user_roles ur JOIN roles r ON r.id = ur.role_id
         WHERE r.name = 'admin' FOR UPDATE OF ur",
    )
    .execute(&mut *tx)
    .await?;
    let others: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_roles ur
         JOIN roles r ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id
         WHERE r.name = 'admin' AND NOT u.disabled AND u.id <> $1",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    Ok(others > 0)
}

async fn is_active_admin(tx: &mut sqlx::PgConnection, user_id: Uuid) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id
                        JOIN users u ON u.id = ur.user_id
                        WHERE ur.user_id = $1 AND r.name = 'admin' AND NOT u.disabled)",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?)
}

pub async fn update_user<'c>(
    db: impl sqlx::Acquire<'c, Database = sqlx::Postgres>,
    user_id: Uuid,
    update: &UserUpdate,
) -> Result<Outcome> {
    let mut tx = db.begin().await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
    if !exists {
        return Ok(Outcome::NotFound);
    }
    let removes_admin =
        update.role.as_deref().is_some_and(|r| r != rbac::ADMIN) || update.disabled == Some(true);
    if removes_admin
        && is_active_admin(&mut tx, user_id).await?
        && !keeps_an_admin(&mut tx, user_id).await?
    {
        return Ok(Outcome::LastAdmin);
    }

    if let Some(role) = &update.role {
        sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = $2",
        )
        .bind(user_id)
        .bind(role)
        .execute(&mut *tx)
        .await?;
    }
    if let Some(hash) = &update.password_hash {
        sqlx::query(
            "UPDATE users SET password_hash = $2, credential_version = credential_version + 1 WHERE id = $1",
        )
        .bind(user_id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    }
    if let Some(disabled) = update.disabled {
        sqlx::query(
            "UPDATE users SET disabled = $2,
                credential_version = credential_version + CASE WHEN $2 THEN 1 ELSE 0 END
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(disabled)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Outcome::Done)
}

pub async fn delete_user<'c>(
    db: impl sqlx::Acquire<'c, Database = sqlx::Postgres>,
    user_id: Uuid,
) -> Result<Outcome> {
    let mut tx = db.begin().await?;
    if is_active_admin(&mut tx, user_id).await? && !keeps_an_admin(&mut tx, user_id).await? {
        return Ok(Outcome::LastAdmin);
    }
    let res = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(if res.rows_affected() == 1 {
        Outcome::Done
    } else {
        Outcome::NotFound
    })
}

/// `true`, jeśli błąd to naruszenie unikalności (np. zajęta nazwa użytkownika).
pub fn is_unique_violation(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(|e| e.as_database_error())
        .is_some_and(|e| e.is_unique_violation())
}

pub async fn create_user<'c>(
    db: impl sqlx::Acquire<'c, Database = sqlx::Postgres>,
    username: &str,
    password_hash: &str,
    role: &str,
) -> Result<Uuid> {
    let mut tx = db.begin().await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
    )
    .bind(username)
    .bind(password_hash)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = $2",
    )
    .bind(id)
    .bind(role)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn find_credentials(db: &PgPool, username: &str) -> Result<Option<Credentials>> {
    Ok(sqlx::query_as::<_, Credentials>(
        "SELECT id, password_hash, credential_version, disabled FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(db)
    .await?)
}

pub async fn profile(db: &PgPool, user_id: Uuid) -> Result<Option<Profile>> {
    let Some(username) =
        sqlx::query_scalar::<_, String>("SELECT username FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await?
    else {
        return Ok(None);
    };
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 ORDER BY r.name",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    let permissions: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT rp.permission FROM user_roles ur
         JOIN role_permissions rp ON rp.role_id = ur.role_id
         WHERE ur.user_id = $1 ORDER BY 1",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(Some(Profile {
        id: user_id,
        username,
        roles,
        permissions,
    }))
}

/// Zwiększa wersję poświadczeń: wszystkie sesje użytkownika przestają być ważne w tej samej chwili.
pub async fn bump_credential_version(db: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET credential_version = credential_version + 1 WHERE id = $1")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Przy pustej tabeli `users` tworzy konto administratora z rolą `admin`.
pub async fn bootstrap_admin(db: &PgPool, password: Option<&str>) -> Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await?;
    if users > 0 {
        tx.commit().await?;
        return Ok(());
    }
    let password = password
        .filter(|p| p.chars().count() >= 10)
        .ok_or_else(|| {
            anyhow::anyhow!("Pierwszy start wymaga ASI_ADMIN_PASSWORD (minimum 10 znaków)")
        })?;
    let hash = password::hash_password(password)?;
    create_user(&mut *tx, "admin", &hash, rbac::ADMIN).await?;
    tx.commit().await?;
    tracing::info!("Utworzono konto administratora");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{seed_roles, MIGRATOR};

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn bootstrap_creates_demo_admin_once(db: PgPool) {
        seed_roles(&db).await.unwrap();
        assert!(bootstrap_admin(&db, None).await.is_err());
        assert!(bootstrap_admin(&db, Some("admin")).await.is_err());
        bootstrap_admin(&db, Some("fixture-password"))
            .await
            .unwrap();
        let creds = find_credentials(&db, "admin").await.unwrap().unwrap();
        assert!(creds.password_hash.starts_with("$argon2id$"));
        assert!(password::verify_password(
            "fixture-password",
            &creds.password_hash
        ));

        let profile = profile(&db, creds.id).await.unwrap().unwrap();
        assert_eq!(profile.roles, vec!["admin"]);
        assert!(profile.permissions.contains(&"admin.users".to_string()));

        bootstrap_admin(&db, None).await.unwrap();
        let again = find_credentials(&db, "admin").await.unwrap().unwrap();
        assert_eq!(again.password_hash, creds.password_hash);
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(users, 1);
    }

    async fn admins_left(db: &PgPool) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id
             JOIN users u ON u.id = ur.user_id WHERE r.name = 'admin' AND NOT u.disabled",
        )
        .fetch_one(db)
        .await
        .unwrap()
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn last_admin_cannot_be_demoted_disabled_or_deleted(db: PgPool) {
        seed_roles(&db).await.unwrap();
        let admin = create_user(&db, "a", "h", rbac::ADMIN).await.unwrap();
        let demote = UserUpdate {
            role: Some(rbac::VIEWER.into()),
            ..Default::default()
        };
        let disable = UserUpdate {
            disabled: Some(true),
            ..Default::default()
        };
        assert_eq!(
            update_user(&db, admin, &demote).await.unwrap(),
            Outcome::LastAdmin
        );
        assert_eq!(
            update_user(&db, admin, &disable).await.unwrap(),
            Outcome::LastAdmin
        );
        assert_eq!(delete_user(&db, admin).await.unwrap(), Outcome::LastAdmin);
        assert_eq!(admins_left(&db).await, 1);

        let second = create_user(&db, "b", "h", rbac::ADMIN).await.unwrap();
        assert_eq!(
            update_user(&db, admin, &demote).await.unwrap(),
            Outcome::Done
        );
        assert_eq!(delete_user(&db, second).await.unwrap(), Outcome::LastAdmin);
        assert_eq!(
            update_user(&db, Uuid::new_v4(), &demote).await.unwrap(),
            Outcome::NotFound
        );
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn concurrent_demotions_keep_one_admin(db: PgPool) {
        seed_roles(&db).await.unwrap();
        for round in 0..10 {
            sqlx::query("DELETE FROM users").execute(&db).await.unwrap();
            let a = create_user(&db, &format!("a{round}"), "h", rbac::ADMIN)
                .await
                .unwrap();
            let b = create_user(&db, &format!("b{round}"), "h", rbac::ADMIN)
                .await
                .unwrap();
            let demote = UserUpdate {
                role: Some(rbac::VIEWER.into()),
                ..Default::default()
            };
            let (ra, rb) = tokio::join!(update_user(&db, a, &demote), update_user(&db, b, &demote));
            let done = [ra.unwrap(), rb.unwrap()]
                .iter()
                .filter(|o| **o == Outcome::Done)
                .count();
            assert_eq!(done, 1, "runda {round}");
            assert_eq!(admins_left(&db).await, 1, "runda {round}");
        }
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn password_change_bumps_credential_version(db: PgPool) {
        seed_roles(&db).await.unwrap();
        let id = create_user(&db, "ola", "h", rbac::VIEWER).await.unwrap();
        let upd = UserUpdate {
            password_hash: Some("nowy".into()),
            ..Default::default()
        };
        update_user(&db, id, &upd).await.unwrap();
        let c = find_credentials(&db, "ola").await.unwrap().unwrap();
        assert_eq!(
            (c.password_hash.as_str(), c.credential_version),
            ("nowy", 2)
        );

        let dup = create_user(&db, "ola", "h", rbac::VIEWER)
            .await
            .unwrap_err();
        assert!(is_unique_violation(&dup));
    }
}

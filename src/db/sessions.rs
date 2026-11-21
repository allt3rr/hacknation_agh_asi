//! Sesje logowania (cookie `asi_session`). W bazie tylko SHA-256 tokenu.

use super::{now, Db};
use anyhow::Result;
use chrono::Utc;

/// Użytkownik ważnej sesji z aktualną rolą z tabeli `users`.
#[derive(Debug, sqlx::FromRow)]
pub struct SessionUser {
    pub id: String,
    pub username: String,
    pub role: String,
}

pub async fn create_session(
    db: &Db,
    token_hash: &str,
    user_id: &str,
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO sessions (id_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(now())
    .bind(expires_at)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn find_session_user(db: &Db, token_hash: &str) -> Result<Option<SessionUser>> {
    let user = sqlx::query_as::<_, SessionUser>(
        "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.id_hash = ? AND s.expires_at > ?",
    )
    .bind(token_hash)
    .bind(Utc::now().timestamp())
    .fetch_optional(db)
    .await?;
    Ok(user)
}

pub async fn delete_session(db: &Db, token_hash: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id_hash = ?")
        .bind(token_hash)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_user_sessions(db: &Db, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_expired_sessions(db: &Db) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(Utc::now().timestamp())
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;
    use crate::db::{connect_memory, create_user};

    #[tokio::test]
    async fn valid_expired_and_deleted_sessions() {
        let db = connect_memory().await.unwrap();
        let user = create_user(&db, "anna", "hash", Role::Viewer)
            .await
            .unwrap();
        let future = Utc::now().timestamp() + 3600;

        create_session(&db, "valid", &user, future).await.unwrap();
        create_session(&db, "expired", &user, Utc::now().timestamp() - 1)
            .await
            .unwrap();

        let found = find_session_user(&db, "valid").await.unwrap().unwrap();
        assert_eq!(
            (found.username.as_str(), found.role.as_str()),
            ("anna", "viewer")
        );
        assert!(find_session_user(&db, "expired").await.unwrap().is_none());

        delete_expired_sessions(&db).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(left, 1);

        delete_session(&db, "valid").await.unwrap();
        assert!(find_session_user(&db, "valid").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deleting_user_removes_sessions() {
        let db = connect_memory().await.unwrap();
        let user = create_user(&db, "jan", "hash", Role::Editor).await.unwrap();
        create_session(&db, "h", &user, Utc::now().timestamp() + 60)
            .await
            .unwrap();

        crate::db::delete_user(&db, &user).await.unwrap();
        assert!(find_session_user(&db, "h").await.unwrap().is_none());
    }
}

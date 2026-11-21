//! Sesje logowania. Klucz to SHA-256 tokenu z cookie; sesja jest ważna tylko przy aktualnej wersji poświadczeń.

use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

/// Zapisuje sesję, jeśli wersja poświadczeń nie zmieniła się od weryfikacji hasła.
/// `false` oznacza, że w międzyczasie zmieniono hasło lub wyłączono konto.
pub async fn create_session(
    db: &PgPool,
    token_hash: &[u8],
    user_id: Uuid,
    credential_version: i32,
    ttl_hours: i64,
    ip: Option<String>,
    user_agent: Option<String>,
) -> Result<bool> {
    let res = sqlx::query(
        "INSERT INTO sessions (id_hash, user_id, credential_version, expires_at, ip, user_agent)
         SELECT $1, u.id, u.credential_version, now() + make_interval(hours => $4), $5::inet, $6
         FROM users u
         WHERE u.id = $2 AND u.credential_version = $3 AND NOT u.disabled",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(credential_version)
    .bind(i32::try_from(ttl_hours)?)
    .bind(ip)
    .bind(user_agent)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Użytkownik ważnej sesji (nie wygasła, aktualna wersja poświadczeń, konto aktywne).
pub async fn find_session_user(db: &PgPool, token_hash: &[u8]) -> Result<Option<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT u.id FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.id_hash = $1 AND s.expires_at > now()
           AND s.credential_version = u.credential_version AND NOT u.disabled",
    )
    .bind(token_hash)
    .fetch_optional(db)
    .await?)
}

pub async fn delete_session(db: &PgPool, token_hash: &[u8]) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id_hash = $1")
        .bind(token_hash)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_expired(db: &PgPool) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE expires_at <= now()")
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{seed_roles, users, MIGRATOR};

    async fn user(db: &PgPool) -> Uuid {
        seed_roles(db).await.unwrap();
        users::create_user(db, "anna", "hash", "viewer")
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn expired_deleted_and_stale_sessions_are_rejected(db: PgPool) {
        let id = user(&db).await;
        assert!(
            create_session(&db, b"ok", id, 1, 12, Some("10.0.0.1".into()), None)
                .await
                .unwrap()
        );
        assert_eq!(find_session_user(&db, b"ok").await.unwrap(), Some(id));

        assert!(create_session(&db, b"old", id, 1, 12, None, None)
            .await
            .unwrap());
        sqlx::query(
            "UPDATE sessions SET expires_at = now() - interval '1 second' WHERE id_hash = $1",
        )
        .bind(&b"old"[..])
        .execute(&db)
        .await
        .unwrap();
        assert_eq!(find_session_user(&db, b"old").await.unwrap(), None);
        delete_expired(&db).await.unwrap();

        delete_session(&db, b"ok").await.unwrap();
        assert_eq!(find_session_user(&db, b"ok").await.unwrap(), None);
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn credential_version_invalidates_and_blocks_race(db: PgPool) {
        let id = user(&db).await;
        assert!(create_session(&db, b"s", id, 1, 12, None, None)
            .await
            .unwrap());

        users::bump_credential_version(&db, id).await.unwrap();
        assert_eq!(find_session_user(&db, b"s").await.unwrap(), None);

        // logowanie zweryfikowane przy wersji 1, zapis po zmianie na 2
        assert!(!create_session(&db, b"race", id, 1, 12, None, None)
            .await
            .unwrap());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE id_hash = $1")
            .bind(&b"race"[..])
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }
}

use super::{new_id, now, Db};
use crate::auth::Role;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub created_at: String,
}

pub async fn count_users(db: &Db) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(db).await?)
}

pub async fn create_user(db: &Db, username: &str, password_hash: &str, role: Role) -> Result<String> {
    let id = new_id();
    sqlx::query("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(username)
        .bind(password_hash)
        .bind(role.as_str())
        .bind(now())
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn find_user_by_name(db: &Db, username: &str) -> Result<Option<UserRow>> {
    let user = sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(db)
        .await?;
    Ok(user)
}

pub async fn list_users(db: &Db) -> Result<Vec<UserRow>> {
    let users = sqlx::query_as::<_, UserRow>("SELECT * FROM users ORDER BY username")
        .fetch_all(db)
        .await?;
    Ok(users)
}

/// Zwraca `false`, jeśli użytkownik nie istnieje.
pub async fn update_user(db: &Db, id: &str, role: Option<Role>, password_hash: Option<String>) -> Result<bool> {
    let mut changed = false;

    if let Some(role) = role {
        let res = sqlx::query("UPDATE users SET role = ? WHERE id = ?")
            .bind(role.as_str())
            .bind(id)
            .execute(db)
            .await?;
        changed |= res.rows_affected() > 0;
    }

    if let Some(hash) = password_hash {
        let res = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(hash)
            .bind(id)
            .execute(db)
            .await?;
        changed |= res.rows_affected() > 0;
    }

    Ok(changed)
}

pub async fn delete_user(db: &Db, id: &str) -> Result<bool> {
    let res = sqlx::query("DELETE FROM users WHERE id = ?").bind(id).execute(db).await?;
    Ok(res.rows_affected() > 0)
}

//! Warstwa danych ASI: pula PostgreSQL, migracje, seed ról i repozytoria.

pub mod audit;
pub mod overrides;
pub mod results;
#[cfg(test)]
mod results_tests;
pub mod rules;
pub mod runs;
pub mod schedule;
pub mod sessions;
pub mod targets;
pub mod users;
pub mod views;
pub mod vulns;
#[cfg(test)]
mod vulns_tests;

use anyhow::{Context, Result};
use asi_core::rbac;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

pub use sqlx::PgPool as Db;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Łączy z bazą; nieosiągalna baza kończy się błędem po kilku sekundach.
pub async fn connect(url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url)
        .await
        .context("Nie można połączyć się z bazą (DATABASE_URL)")
}

/// Migracje, seed ról i konto admina. Bezpieczne do wielokrotnego wywołania.
pub async fn prepare(db: &PgPool, password: Option<&str>) -> Result<()> {
    MIGRATOR
        .run(db)
        .await
        .context("Migracje bazy nie powiodły się")?;
    seed_roles(db).await?;
    users::bootstrap_admin(db, password).await?;
    Ok(())
}

/// Wbudowane role i uprawnienia z macierzy `asi_core::rbac` (idempotentnie).
pub async fn seed_roles(db: &PgPool) -> Result<()> {
    let mut tx = db.begin().await?;
    for code in rbac::ALL_PERMISSIONS {
        sqlx::query("INSERT INTO permissions (code) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(code)
            .execute(&mut *tx)
            .await?;
    }
    for role in rbac::BUILTIN_ROLES {
        sqlx::query(
            "INSERT INTO roles (name, builtin) VALUES ($1, true) ON CONFLICT (name) DO NOTHING",
        )
        .bind(role)
        .execute(&mut *tx)
        .await?;
        for code in rbac::role_permissions(role) {
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission)
                 SELECT id, $2 FROM roles WHERE name = $1
                 ON CONFLICT DO NOTHING",
            )
            .bind(role)
            .bind(code)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn count(db: &PgPool, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(db)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn seed_is_idempotent(db: PgPool) {
        seed_roles(&db).await.unwrap();
        let roles = count(&db, "roles").await;
        let grants = count(&db, "role_permissions").await;
        seed_roles(&db).await.unwrap();

        assert_eq!(roles, 4);
        assert_eq!(count(&db, "roles").await, roles);
        assert_eq!(count(&db, "role_permissions").await, grants);

        let builtin: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE builtin")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(builtin, 4);
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn migration_creates_all_tables(db: PgPool) {
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema() AND tablename <> '_sqlx_migrations' ORDER BY 1",
        )
        .fetch_all(&db)
        .await
        .unwrap();
        let mut expected = vec![
            "assets",
            "audit_log",
            "changes",
            "http_info",
            "observations",
            "overrides",
            "permissions",
            "role_permissions",
            "roles",
            "rules",
            "scan_chunks",
            "scan_runs",
            "scan_schedule",
            "services",
            "sessions",
            "targets",
            "user_roles",
            "users",
            "cve_cache",
            "vulnerabilities",
        ];
        expected.sort_unstable();
        assert_eq!(tables, expected);
    }
}

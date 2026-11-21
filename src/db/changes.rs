use super::crypto::FieldCrypto;
use super::{now, Db};
use crate::diff::{Change, ChangeKind};
use anyhow::Result;

#[derive(sqlx::FromRow)]
struct ChangeRow {
    kind: String,
    key: String,
    ip: String,
    field: Option<String>,
    before_enc: Option<String>,
    after_enc: Option<String>,
}

pub async fn insert_changes(db: &Db, crypto: &FieldCrypto, run_id: &str, changes: &[Change]) -> Result<()> {
    let mut tx = db.begin().await?;
    for change in changes {
        sqlx::query(
            "INSERT INTO changes (run_id, kind, key, ip, field, before_enc, after_enc, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(run_id)
        .bind(change.kind.as_str())
        .bind(change.key.as_str())
        .bind(change.ip.as_str())
        .bind(change.field.clone())
        .bind(crypto.encrypt_opt(change.before.as_deref())?)
        .bind(crypto.encrypt_opt(change.after.as_deref())?)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn list_changes(db: &Db, crypto: &FieldCrypto, run_id: &str, limit: i64) -> Result<Vec<Change>> {
    let rows = sqlx::query_as::<_, ChangeRow>(
        "SELECT kind, key, ip, field, before_enc, after_enc
         FROM changes
         WHERE run_id = ?
         ORDER BY id
         LIMIT ?",
    )
    .bind(run_id)
    .bind(limit)
    .fetch_all(db)
    .await?;

    let mut changes = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(kind) = ChangeKind::parse(&row.kind) else {
            continue;
        };
        changes.push(Change {
            kind,
            key: row.key,
            ip: row.ip,
            field: row.field,
            before: crypto.decrypt_opt(row.before_enc.as_deref())?,
            after: crypto.decrypt_opt(row.after_enc.as_deref())?,
        });
    }
    Ok(changes)
}

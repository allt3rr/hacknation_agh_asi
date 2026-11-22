//! Korekty analityka: trwałe, z historią i autorem, niezależne od kolejnych skanów.

use anyhow::Result;
use asi_crypto::{aad, FieldCrypto};
use serde::Serialize;
use sqlx::PgPool;
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

pub const ENTITY: &str = "service";
pub const FIELDS: &[&str] = &[
    "product", "version", "service", "status", "severity", "owner", "note",
];
pub const STATUSES: &[&str] = &["open", "false_positive", "accepted", "fixed"];

#[derive(Debug, Serialize)]
pub struct OverrideRow {
    pub id: Uuid,
    pub field: String,
    pub value: Option<String>,
    pub reason: Option<String>,
    pub author: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

fn value_aad(id: Uuid) -> String {
    aad("overrides", "value_enc", id)
}

/// Zastępuje aktywną korektę pola nową (poprzednia zostaje w historii z `revoked_at`).
pub async fn set(
    db: &PgPool,
    crypto: &FieldCrypto,
    key: &str,
    field: &str,
    value: &str,
    reason: Option<&str>,
    author: Uuid,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let enc = crypto.encrypt_str(&value_aad(id), value)?;
    let mut tx = db.begin().await?;
    sqlx::query(
        "UPDATE overrides SET revoked_at = now()
         WHERE entity_type = $1 AND entity_key = $2 AND field = $3 AND revoked_at IS NULL",
    )
    .bind(ENTITY)
    .bind(key)
    .bind(field)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO overrides (id, entity_type, entity_key, field, value_enc, reason, author)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(ENTITY)
    .bind(key)
    .bind(field)
    .bind(&enc)
    .bind(reason)
    .bind(author)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn revoke(db: &PgPool, key: &str, field: &str) -> Result<bool> {
    let res = sqlx::query(
        "UPDATE overrides SET revoked_at = now()
         WHERE entity_type = $1 AND entity_key = $2 AND field = $3 AND revoked_at IS NULL",
    )
    .bind(ENTITY)
    .bind(key)
    .bind(field)
    .execute(db)
    .await?;
    Ok(res.rows_affected() > 0)
}

type Row = (
    Uuid,
    String,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    OffsetDateTime,
    Option<OffsetDateTime>,
);

pub async fn history(db: &PgPool, crypto: &FieldCrypto, key: &str) -> Result<Vec<OverrideRow>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT o.id, o.field, o.value_enc, o.reason, u.username, o.created_at, o.revoked_at
         FROM overrides o LEFT JOIN users u ON u.id = o.author
         WHERE o.entity_type = $1 AND o.entity_key = $2 ORDER BY o.created_at DESC, o.field",
    )
    .bind(ENTITY)
    .bind(key)
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|(id, field, enc, reason, author, created_at, revoked_at)| {
            let value = enc
                .map(|v| crypto.decrypt_str(&value_aad(id), &v))
                .transpose()?;
            Ok(OverrideRow {
                id,
                field,
                value,
                reason,
                author,
                created_at,
                revoked_at,
            })
        })
        .collect()
}

/// Aktywne korekty dla podanych kluczy usług: klucz → pole → wartość.
pub async fn active_for(
    db: &PgPool,
    crypto: &FieldCrypto,
    keys: &[String],
) -> Result<HashMap<String, HashMap<String, String>>> {
    let rows: Vec<(Uuid, String, String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT id, entity_key, field, value_enc FROM overrides
         WHERE entity_type = $1 AND entity_key = ANY($2) AND revoked_at IS NULL",
    )
    .bind(ENTITY)
    .bind(keys)
    .fetch_all(db)
    .await?;
    let mut out: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (id, key, field, enc) in rows {
        if let Some(enc) = enc {
            out.entry(key)
                .or_default()
                .insert(field, crypto.decrypt_str(&value_aad(id), &enc)?);
        }
    }
    Ok(out)
}

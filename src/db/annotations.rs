//! Ręczne adnotacje analityków do usług (klucz `ip:port/proto`).
//! Są przechowywane osobno od wyników, więc przetrwają kolejne skany.

use super::crypto::FieldCrypto;
use super::{join_tags, now, Db};
use crate::input::split_list;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub key: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub updated_by: String,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(sqlx::FromRow)]
struct AnnotationRow {
    key: String,
    tags: String,
    note_enc: Option<String>,
    severity: Option<String>,
    updated_by: String,
    updated_at: String,
}

pub async fn upsert_annotation(db: &Db, crypto: &FieldCrypto, annotation: &Annotation, user: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO annotations (key, tags, note_enc, severity, updated_by, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET
             tags = excluded.tags,
             note_enc = excluded.note_enc,
             severity = excluded.severity,
             updated_by = excluded.updated_by,
             updated_at = excluded.updated_at",
    )
    .bind(annotation.key.as_str())
    .bind(join_tags(&annotation.tags))
    .bind(crypto.encrypt_opt(annotation.note.as_deref())?)
    .bind(annotation.severity.clone())
    .bind(user)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_annotations(db: &Db, crypto: &FieldCrypto) -> Result<Vec<Annotation>> {
    let rows = sqlx::query_as::<_, AnnotationRow>("SELECT * FROM annotations ORDER BY key")
        .fetch_all(db)
        .await?;

    rows.into_iter()
        .map(|row| {
            Ok(Annotation {
                tags: split_list(&row.tags, ','),
                note: crypto.decrypt_opt(row.note_enc.as_deref())?,
                key: row.key,
                severity: row.severity,
                updated_by: row.updated_by,
                updated_at: row.updated_at,
            })
        })
        .collect()
}

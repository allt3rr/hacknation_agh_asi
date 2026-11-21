use super::crypto::FieldCrypto;
use super::{join_tags, new_id, now, Db};
use crate::input::split_list;
use crate::model::{Target, TargetKind};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(sqlx::FromRow)]
struct TargetRow {
    id: String,
    value: String,
    kind: String,
    tags: String,
    note_enc: Option<String>,
    enabled: i64,
    source: String,
    created_at: String,
    updated_at: String,
}

/// Cel w postaci zwracanej przez API (notatka odszyfrowana).
#[derive(Debug, Serialize)]
pub struct TargetView {
    pub id: String,
    pub value: String,
    pub kind: String,
    pub tags: Vec<String>,
    pub note: Option<String>,
    pub enabled: bool,
    pub source: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Częściowa zmiana celu. Pole `None` oznacza "bez zmian",
/// pusty string w `note` usuwa notatkę.
#[derive(Debug, Default, Deserialize)]
pub struct TargetPatch {
    pub tags: Option<Vec<String>>,
    pub note: Option<String>,
    pub enabled: Option<bool>,
}

/// Dodaje nowe cele. Istniejące nie są nadpisywane, więc ręczne edycje
/// przetrwają ponowny import tego samego pliku.
pub async fn insert_targets(db: &Db, crypto: &FieldCrypto, targets: &[Target], source: &str) -> Result<u64> {
    let mut tx = db.begin().await?;
    let mut inserted = 0;

    for target in targets {
        let timestamp = now();
        let res = sqlx::query(
            "INSERT INTO targets (id, value, kind, tags, note_enc, enabled, source, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
             ON CONFLICT(value) DO NOTHING",
        )
        .bind(new_id())
        .bind(target.value.as_str())
        .bind(target.kind.as_str())
        .bind(join_tags(&target.tags))
        .bind(crypto.encrypt_opt(target.note.as_deref())?)
        .bind(source)
        .bind(&timestamp)
        .bind(&timestamp)
        .execute(&mut *tx)
        .await?;
        inserted += res.rows_affected();
    }

    tx.commit().await?;
    Ok(inserted)
}

pub async fn list_targets(db: &Db, crypto: &FieldCrypto) -> Result<Vec<TargetView>> {
    let rows = sqlx::query_as::<_, TargetRow>("SELECT * FROM targets ORDER BY created_at, value")
        .fetch_all(db)
        .await?;

    rows.into_iter()
        .map(|row| {
            Ok(TargetView {
                note: crypto.decrypt_opt(row.note_enc.as_deref())?,
                tags: split_list(&row.tags, ','),
                enabled: row.enabled != 0,
                id: row.id,
                value: row.value,
                kind: row.kind,
                source: row.source,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
        })
        .collect()
}

/// Zwraca `false`, jeśli cel nie istnieje.
pub async fn update_target(db: &Db, crypto: &FieldCrypto, id: &str, patch: TargetPatch) -> Result<bool> {
    let row = sqlx::query_as::<_, TargetRow>("SELECT * FROM targets WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?;
    let Some(row) = row else {
        return Ok(false);
    };

    let tags = match patch.tags {
        Some(tags) => join_tags(&tags),
        None => row.tags,
    };
    let note_enc = match patch.note {
        Some(note) => crypto.encrypt_opt(Some(note.as_str()))?,
        None => row.note_enc,
    };
    let enabled = patch.enabled.map(i64::from).unwrap_or(row.enabled);

    sqlx::query("UPDATE targets SET tags = ?, note_enc = ?, enabled = ?, updated_at = ? WHERE id = ?")
        .bind(tags)
        .bind(note_enc)
        .bind(enabled)
        .bind(now())
        .bind(id)
        .execute(db)
        .await?;
    Ok(true)
}

pub async fn delete_target(db: &Db, id: &str) -> Result<bool> {
    let res = sqlx::query("DELETE FROM targets WHERE id = ?").bind(id).execute(db).await?;
    Ok(res.rows_affected() > 0)
}

/// Cele z włączonym skanowaniem.
pub async fn enabled_targets(db: &Db) -> Result<Vec<Target>> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT value, kind, tags FROM targets WHERE enabled = 1")
            .fetch_all(db)
            .await?;

    let targets = rows
        .into_iter()
        .filter_map(|(value, kind, tags)| {
            Some(Target {
                value,
                kind: TargetKind::parse(&kind)?,
                tags: split_list(&tags, ','),
                note: None,
            })
        })
        .collect();
    Ok(targets)
}

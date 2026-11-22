//! Cele skanowania. Edycje użytkownika są trwałe: ponowny import nie nadpisuje istniejących celów.

use anyhow::Result;
use asi_core::targets::Target;
use asi_crypto::{aad, FieldCrypto};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct TargetView {
    pub id: Uuid,
    pub kind: String,
    pub value: String,
    pub source: String,
    pub excluded: bool,
    pub tags: Vec<String>,
    pub note: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(sqlx::FromRow)]
struct TargetRow {
    id: Uuid,
    kind: String,
    value: String,
    source: String,
    excluded: bool,
    tags: Vec<String>,
    note_enc: Option<Vec<u8>>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

/// Pusty string w `note` usuwa notatkę.
#[derive(Debug, Default, Deserialize)]
pub struct TargetPatch {
    pub tags: Option<Vec<String>>,
    pub note: Option<String>,
    pub excluded: Option<bool>,
}

fn note_aad(id: Uuid) -> String {
    aad("targets", "note_enc", id)
}

/// Zapisuje cele wsadowo; istniejące `(kind, value)` są pomijane. Zwraca liczbę nowych.
pub async fn insert_targets(
    db: &PgPool,
    crypto: &FieldCrypto,
    targets: &[Target],
    source: &str,
    created_by: Option<Uuid>,
) -> Result<u64> {
    let mut ids = Vec::with_capacity(targets.len());
    let mut kinds = Vec::with_capacity(targets.len());
    let mut values = Vec::with_capacity(targets.len());
    let mut tags = Vec::with_capacity(targets.len());
    let mut notes: Vec<Option<Vec<u8>>> = Vec::with_capacity(targets.len());
    for t in targets {
        let id = Uuid::new_v4();
        notes.push(
            t.note
                .as_deref()
                .filter(|n| !n.is_empty())
                .map(|n| crypto.encrypt_str(&note_aad(id), n))
                .transpose()?,
        );
        ids.push(id);
        kinds.push(t.kind.as_str());
        values.push(t.value.as_str());
        // tablice tagów o różnej długości nie przejdą przez UNNEST; przekazujemy je jako tekst
        tags.push(serde_json::to_string(&t.tags)?);
    }
    let res = sqlx::query(
        "INSERT INTO targets (id, kind, value, source, tags, note_enc, created_by)
         SELECT u.id, u.kind, u.value, $4,
                ARRAY(SELECT jsonb_array_elements_text(u.tags::jsonb)), u.note, $7
         FROM UNNEST($1::uuid[], $2::text[], $3::text[], $5::text[], $6::bytea[])
              AS u(id, kind, value, tags, note)
         ON CONFLICT (kind, value) DO NOTHING",
    )
    .bind(&ids)
    .bind(&kinds)
    .bind(&values)
    .bind(source)
    .bind(&tags)
    .bind(&notes)
    .bind(created_by)
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

/// Ile z podanych celów już istnieje w bazie (do raportu `dry_run`).
pub async fn count_existing(db: &PgPool, targets: &[Target]) -> Result<i64> {
    let kinds: Vec<&str> = targets.iter().map(|t| t.kind.as_str()).collect();
    let values: Vec<&str> = targets.iter().map(|t| t.value.as_str()).collect();
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM targets t JOIN UNNEST($1::text[], $2::text[]) AS u(kind, value)
         ON t.kind = u.kind AND t.value = u.value",
    )
    .bind(&kinds)
    .bind(&values)
    .fetch_one(db)
    .await?)
}

pub async fn list_targets(db: &PgPool, crypto: &FieldCrypto) -> Result<Vec<TargetView>> {
    let rows = sqlx::query_as::<_, TargetRow>(
        "SELECT id, kind, value, source, excluded, tags, note_enc, created_at, updated_at
         FROM targets ORDER BY created_at, value",
    )
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|r| {
            let note = r
                .note_enc
                .as_deref()
                .map(|n| crypto.decrypt_str(&note_aad(r.id), n))
                .transpose()?;
            Ok(TargetView {
                id: r.id,
                kind: r.kind,
                value: r.value,
                source: r.source,
                excluded: r.excluded,
                tags: r.tags,
                note,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
        })
        .collect()
}

/// `false`, gdy cel nie istnieje.
pub async fn update_target(
    db: &PgPool,
    crypto: &FieldCrypto,
    id: Uuid,
    patch: &TargetPatch,
) -> Result<bool> {
    let note = patch
        .note
        .as_deref()
        .map(|n| {
            (!n.is_empty())
                .then(|| crypto.encrypt_str(&note_aad(id), n))
                .transpose()
        })
        .transpose()?;
    let res = sqlx::query(
        "UPDATE targets SET
            tags = COALESCE($2, tags),
            note_enc = CASE WHEN $3 THEN $4 ELSE note_enc END,
            excluded = COALESCE($5, excluded),
            updated_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(&patch.tags)
    .bind(note.is_some())
    .bind(note.flatten())
    .bind(patch.excluded)
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn delete_target(db: &PgPool, id: Uuid) -> Result<bool> {
    let res = sqlx::query("DELETE FROM targets WHERE id = $1")
        .bind(id)
        .execute(db)
        .await?;
    Ok(res.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MIGRATOR;
    use asi_core::targets::parse_text;

    fn crypto() -> FieldCrypto {
        FieldCrypto::from_base64(&FieldCrypto::generate_key()).unwrap()
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn reimport_keeps_user_edits(db: PgPool) {
        let c = crypto();
        let report = parse_text("10.0.0.1 10.0.0.0/24 a.pl");
        assert_eq!(
            insert_targets(&db, &c, &report.targets, "manual", None)
                .await
                .unwrap(),
            3
        );

        let id = list_targets(&db, &c).await.unwrap()[0].id;
        let patch = TargetPatch {
            tags: Some(vec!["dmz".into()]),
            ..Default::default()
        };
        assert!(update_target(&db, &c, id, &patch).await.unwrap());

        assert_eq!(
            insert_targets(&db, &c, &report.targets, "csv", None)
                .await
                .unwrap(),
            0
        );
        let after = list_targets(&db, &c).await.unwrap();
        assert_eq!(after.len(), 3);
        assert_eq!(after.iter().find(|t| t.id == id).unwrap().tags, vec!["dmz"]);
    }

    #[sqlx::test(migrator = "MIGRATOR")]
    async fn note_is_encrypted_and_bound_to_record(db: PgPool) {
        let c = crypto();
        let report = parse_text("10.0.0.1 10.0.0.2");
        insert_targets(&db, &c, &report.targets, "manual", None)
            .await
            .unwrap();
        let list = list_targets(&db, &c).await.unwrap();
        let (a, b) = (list[0].id, list[1].id);

        let patch = TargetPatch {
            note: Some("serwer księgowości".into()),
            ..Default::default()
        };
        update_target(&db, &c, a, &patch).await.unwrap();
        let view = list_targets(&db, &c).await.unwrap();
        assert_eq!(
            view.iter().find(|t| t.id == a).unwrap().note.as_deref(),
            Some("serwer księgowości")
        );

        let raw: Vec<u8> = sqlx::query_scalar("SELECT note_enc FROM targets WHERE id = $1")
            .bind(a)
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("księgowości"));

        sqlx::query("UPDATE targets SET note_enc = $1 WHERE id = $2")
            .bind(&raw)
            .bind(b)
            .execute(&db)
            .await
            .unwrap();
        assert!(list_targets(&db, &c).await.is_err());

        let clear = TargetPatch {
            note: Some(String::new()),
            ..Default::default()
        };
        update_target(&db, &c, b, &clear).await.unwrap();
        assert!(list_targets(&db, &c).await.is_ok());
    }
}

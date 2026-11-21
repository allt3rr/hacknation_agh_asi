use super::crypto::FieldCrypto;
use super::Db;
use crate::model::Observation;
use anyhow::Result;

/// Cała obserwacja (nagłówki, ciasteczka, certyfikat, bannery) jest zapisywana zaszyfrowana.
/// Jawnie trzymamy tylko pola potrzebne do wyszukiwania.
pub async fn insert_observations(db: &Db, crypto: &FieldCrypto, run_id: &str, observations: &[Observation]) -> Result<()> {
    let mut tx = db.begin().await?;
    for obs in observations {
        sqlx::query(
            "INSERT INTO observations (run_id, ip, port, proto, service, data_enc)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(run_id)
        .bind(obs.ip.as_str())
        .bind(i64::from(obs.port))
        .bind(obs.proto.as_str())
        .bind(obs.service.clone())
        .bind(crypto.encrypt_json(obs)?)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn load_observations(db: &Db, crypto: &FieldCrypto, run_id: &str) -> Result<Vec<Observation>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT data_enc FROM observations WHERE run_id = ? ORDER BY ip, port")
        .bind(run_id)
        .fetch_all(db)
        .await?;
    rows.iter().map(|(data,)| crypto.decrypt_json(data)).collect()
}

/// Ostatni znany stan każdego hosta, który nie jest oznaczony jako nieaktywny.
/// Dla każdego hosta bierzemy usługi z przebiegu, w którym ostatnio odpowiedział.
pub async fn load_baseline(db: &Db, crypto: &FieldCrypto) -> Result<Vec<Observation>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT o.data_enc
         FROM observations o
         JOIN host_state h ON h.ip = o.ip AND h.last_seen_run = o.run_id
         WHERE h.status != 'inactive'",
    )
    .fetch_all(db)
    .await?;
    rows.iter().map(|(data,)| crypto.decrypt_json(data)).collect()
}

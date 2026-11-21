use crate::config::Config;
use crate::db::{self, crypto::FieldCrypto, Db};
use crate::fingerprint::SignatureSet;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: Db,
    pub crypto: Arc<FieldCrypto>,
    pub signatures: Arc<RwLock<SignatureSet>>,
    /// tylko jeden skan/import naraz
    pub scan_lock: Arc<Mutex<()>>,
}

impl AppState {
    pub async fn init(cfg: Config) -> Result<Self> {
        let key = std::env::var("ASI_DATA_KEY").context("Brak ASI_DATA_KEY w środowisku/.env (wygeneruj: asi gen-key)")?;
        let crypto = FieldCrypto::from_base64_key(&key)?;
        let db = db::connect(&cfg.database.url).await?;
        let st = Self {
            cfg: Arc::new(cfg),
            db,
            crypto: Arc::new(crypto),
            signatures: Arc::new(RwLock::new(SignatureSet::default())),
            scan_lock: Arc::new(Mutex::new(())),
        };
        let n = st.reload_signatures().await?;
        tracing::info!("Załadowano {n} sygnatur");
        Ok(st)
    }

    /// Stan do testów API: konfiguracja z `config/asi.toml`, podana baza, losowy klucz, bez sygnatur.
    #[cfg(test)]
    pub fn for_tests(db: Db, edit: impl FnOnce(&mut Config)) -> Self {
        let mut cfg: Config = toml::from_str(include_str!("../config/asi.toml")).expect("config/asi.toml");
        edit(&mut cfg);
        let crypto = FieldCrypto::from_base64_key(&FieldCrypto::generate_key()).expect("klucz");
        Self {
            cfg: Arc::new(cfg),
            db,
            crypto: Arc::new(crypto),
            signatures: Arc::new(RwLock::new(SignatureSet::default())),
            scan_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Wbudowane sygnatury z katalogu + własne z bazy (własne nadpisują wbudowane o tym samym id).
    pub async fn reload_signatures(&self) -> Result<usize> {
        let mut sigs = SignatureSet::load_dir(Path::new(&self.cfg.signatures_dir))?;
        for row in db::list_signatures(&self.db).await? {
            if row.enabled == 0 {
                continue;
            }
            match SignatureSet::parse_yaml(&row.yaml) {
                Ok(s) => sigs.extend(s),
                Err(e) => tracing::warn!(name = %row.name, error = %e, "pominięto uszkodzoną sygnaturę"),
            }
        }
        let set = SignatureSet::new(sigs)?;
        let n = set.len();
        *self.signatures.write().await = set;
        Ok(n)
    }

    pub fn scan_running(&self) -> bool {
        self.scan_lock.try_lock().is_err()
    }
}

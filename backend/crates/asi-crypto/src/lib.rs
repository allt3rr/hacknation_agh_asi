//! Szyfrowanie wrażliwych pól (§15): AES-256-GCM, losowy nonce, AAD `tabela:kolumna:id`.
//! Format: `0x01 || nonce[12] || ciphertext+tag`. Bajt wersji zostawia miejsce na `key_id` (rotacja).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;

const VERSION: u8 = 1;

/// shortcut: jeden klucz bez rotacji; envelope encryption (KEK/DEK, `key_id`) przy wdrożeniu produkcyjnym.
pub struct FieldCrypto {
    cipher: Aes256Gcm,
}

/// Skąd pochodzi klucz — tryb demo jest jawnie odróżniony od produkcyjnego.
#[derive(Debug, PartialEq, Eq)]
pub enum KeySource {
    Env,
    File(String),
    Demo,
}

impl FieldCrypto {
    pub fn from_base64(key: &str) -> Result<Self> {
        let raw = STANDARD
            .decode(key.trim())
            .context("Klucz: niepoprawny base64")?;
        if raw.len() != 32 {
            bail!("Klucz musi mieć 32 bajty (ma {})", raw.len());
        }
        Ok(Self {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&raw)),
        })
    }

    pub fn generate_key() -> String {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        STANDARD.encode(k)
    }

    /// Klucz z `ASI_MASTER_KEY`, potem z pliku `ASI_MASTER_KEY_FILE`, potem tryb demo (`ASI_DEMO_KEY=1`).
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<(Self, KeySource)> {
        if let Some(key) = get("ASI_MASTER_KEY").filter(|k| !k.is_empty()) {
            return Ok((Self::from_base64(&key)?, KeySource::Env));
        }
        if let Some(path) = get("ASI_MASTER_KEY_FILE").filter(|p| !p.is_empty()) {
            let key = std::fs::read_to_string(&path)
                .with_context(|| format!("Nie można odczytać ASI_MASTER_KEY_FILE ({path})"))?;
            return Ok((Self::from_base64(&key)?, KeySource::File(path)));
        }
        if get("ASI_DEMO_KEY").as_deref() == Some("1") {
            return Ok((Self::from_base64(&Self::generate_key())?, KeySource::Demo));
        }
        bail!("Brak klucza szyfrowania: ustaw ASI_MASTER_KEY lub ASI_MASTER_KEY_FILE (albo ASI_DEMO_KEY=1 na demo)")
    }

    pub fn encrypt(&self, aad: &str, plain: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("szyfrowanie nie powiodło się"))?;
        let mut out = Vec::with_capacity(1 + 12 + ct.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(&self, aad: &str, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 13 || data[0] != VERSION {
            bail!("nieznany format szyfrogramu");
        }
        let (nonce, ct) = data[1..].split_at(12);
        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("deszyfrowanie nie powiodło się (zły klucz lub rekord)"))
    }

    pub fn encrypt_str(&self, aad: &str, s: &str) -> Result<Vec<u8>> {
        self.encrypt(aad, s.as_bytes())
    }

    pub fn decrypt_str(&self, aad: &str, data: &[u8]) -> Result<String> {
        Ok(String::from_utf8(self.decrypt(aad, data)?)?)
    }
}

/// AAD wiążące szyfrogram z rekordem i kolumną.
pub fn aad(table: &str, column: &str, id: impl std::fmt::Display) -> String {
    format!("{table}:{column}:{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> FieldCrypto {
        FieldCrypto::from_base64(&FieldCrypto::generate_key()).unwrap()
    }

    #[test]
    fn round_trip_and_binding() {
        let c = crypto();
        let a = aad("targets", "note_enc", 1);
        let enc = c.encrypt_str(&a, "serwer księgowości").unwrap();
        assert!(!String::from_utf8_lossy(&enc).contains("serwer"));
        assert_eq!(c.decrypt_str(&a, &enc).unwrap(), "serwer księgowości");

        assert!(c.decrypt_str(&aad("targets", "note_enc", 2), &enc).is_err());
        assert!(crypto().decrypt_str(&a, &enc).is_err());
        assert!(c.decrypt_str(&a, &enc[..5]).is_err());
    }

    #[test]
    fn key_sources() {
        let key = FieldCrypto::generate_key();
        let env = |name: &str| (name == "ASI_MASTER_KEY").then(|| key.clone());
        assert_eq!(FieldCrypto::from_env(env).unwrap().1, KeySource::Env);

        let demo = |name: &str| (name == "ASI_DEMO_KEY").then(|| "1".to_string());
        assert_eq!(FieldCrypto::from_env(demo).unwrap().1, KeySource::Demo);

        assert!(FieldCrypto::from_env(|_| None).is_err());
        let bad = |name: &str| (name == "ASI_MASTER_KEY").then(|| "krótki".to_string());
        assert!(FieldCrypto::from_env(bad).is_err());
    }
}

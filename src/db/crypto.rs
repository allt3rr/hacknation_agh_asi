//! Szyfrowanie danych w spoczynku: AES-256-GCM na poziomie pól (losowy nonce per wartość).
//! Format: base64(nonce[12] || ciphertext+tag).
//!
//! Dodatkowo można włączyć SQLCipher, który szyfruje cały plik bazy.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub struct FieldCrypto {
    cipher: Aes256Gcm,
}

impl FieldCrypto {
    pub fn from_base64_key(key: &str) -> Result<Self> {
        let raw = STANDARD.decode(key.trim()).context("ASI_DATA_KEY: niepoprawny base64")?;
        if raw.len() != 32 {
            bail!("ASI_DATA_KEY musi mieć 32 bajty (ma {})", raw.len());
        }
        Ok(Self { cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&raw)) })
    }

    pub fn generate_key() -> String {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        STANDARD.encode(k)
    }

    pub fn encrypt(&self, plain: &[u8]) -> Result<String> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plain)
            .map_err(|_| anyhow!("szyfrowanie nie powiodło się"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(STANDARD.encode(out))
    }

    pub fn decrypt(&self, data: &str) -> Result<Vec<u8>> {
        let raw = STANDARD.decode(data)?;
        if raw.len() < 12 {
            bail!("zaszyfrowana wartość jest za krótka");
        }
        let (nonce, ct) = raw.split_at(12);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| anyhow!("deszyfrowanie nie powiodło się (zły ASI_DATA_KEY?)"))
    }

    pub fn encrypt_str(&self, s: &str) -> Result<String> {
        self.encrypt(s.as_bytes())
    }

    pub fn decrypt_str(&self, s: &str) -> Result<String> {
        Ok(String::from_utf8(self.decrypt(s)?)?)
    }

    pub fn encrypt_opt(&self, s: Option<&str>) -> Result<Option<String>> {
        s.filter(|v| !v.is_empty()).map(|v| self.encrypt_str(v)).transpose()
    }

    pub fn decrypt_opt(&self, s: Option<&str>) -> Result<Option<String>> {
        s.map(|v| self.decrypt_str(v)).transpose()
    }

    pub fn encrypt_json<T: Serialize>(&self, v: &T) -> Result<String> {
        self.encrypt(&serde_json::to_vec(v)?)
    }

    pub fn decrypt_json<T: DeserializeOwned>(&self, s: &str) -> Result<T> {
        Ok(serde_json::from_slice(&self.decrypt(s)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let c = FieldCrypto::from_base64_key(&FieldCrypto::generate_key()).unwrap();
        let e = c.encrypt_str("Set-Cookie: session=abc").unwrap();
        assert_ne!(e, "Set-Cookie: session=abc");
        assert_eq!(c.decrypt_str(&e).unwrap(), "Set-Cookie: session=abc");
        let other = FieldCrypto::from_base64_key(&FieldCrypto::generate_key()).unwrap();
        assert!(other.decrypt_str(&e).is_err());
    }
}

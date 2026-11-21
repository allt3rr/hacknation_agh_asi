//! Hasła (Argon2id) i tokeny sesji. Te funkcje są kosztowne — w API wywołuj je w `spawn_blocking`.

use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(hash.to_string())
}

/// `false` także dla niepoprawnego formatu hasha.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Losowy token sesji: 32 bajty, base64url bez paddingu.
pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 tokenu — tylko ta wartość trafia do bazy.
pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_round_trip() {
        let hash = hash_password("tajne-haslo").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("tajne-haslo", &hash));
        assert!(!verify_password("zle", &hash));
        assert!(!verify_password("x", "nie-hash"));
    }

    #[test]
    fn token_has_32_random_bytes() {
        let token = new_token();
        assert_eq!(URL_SAFE_NO_PAD.decode(&token).unwrap().len(), 32);
        assert_ne!(token, new_token());
        assert_eq!(token_hash(&token).len(), 32);
    }
}

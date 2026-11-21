//! Ochrona logowania: Argon2 poza wątkami Tokio z limitem równoległości, hash zastępczy
//! dla nieznanych kont i limit nieudanych prób na nazwę użytkownika i adres IP.

use anyhow::Result;
use asi_core::password;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const MAX_PARALLEL_VERIFICATIONS: usize = 4;
pub const MAX_FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(15 * 60);

/// shortcut: liczniki w pamięci procesu, zerowane przy restarcie; przenieść do bazy przy wielu instancjach API.
pub struct LoginGuard {
    verifications: Semaphore,
    dummy_hash: String,
    failures: Mutex<HashMap<String, (u32, Instant)>>,
}

impl LoginGuard {
    pub fn new() -> Result<Self> {
        Ok(Self {
            verifications: Semaphore::new(MAX_PARALLEL_VERIFICATIONS),
            dummy_hash: password::hash_password(&password::new_token())?,
            failures: Mutex::default(),
        })
    }

    /// Weryfikuje hasło. Dla `None` (nieznane konto) liczy Argon2 na hashu zastępczym i zwraca `false`.
    pub async fn verify(&self, password: String, hash: Option<String>) -> bool {
        let known = hash.is_some();
        let hash = hash.unwrap_or_else(|| self.dummy_hash.clone());
        let Ok(_permit) = self.verifications.acquire().await else {
            return false;
        };
        let ok = tokio::task::spawn_blocking(move || password::verify_password(&password, &hash))
            .await
            .unwrap_or(false);
        ok && known
    }

    pub fn is_blocked(&self, keys: &[String]) -> bool {
        let mut map = self.failures.lock().unwrap();
        map.retain(|_, (_, start)| start.elapsed() < WINDOW);
        keys.iter()
            .any(|k| map.get(k).is_some_and(|(n, _)| *n >= MAX_FAILURES))
    }

    pub fn record_failure(&self, keys: &[String]) {
        let mut map = self.failures.lock().unwrap();
        for key in keys {
            map.entry(key.clone()).or_insert((0, Instant::now())).0 += 1;
        }
    }

    pub fn reset(&self, key: &str) {
        self.failures.lock().unwrap().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_per_key() {
        let guard = LoginGuard::new().unwrap();
        let keys = vec!["user:a".to_string()];
        for _ in 0..MAX_FAILURES {
            assert!(!guard.is_blocked(&keys));
            guard.record_failure(&keys);
        }
        assert!(guard.is_blocked(&keys));
        assert!(!guard.is_blocked(&["user:b".to_string()]));
        guard.reset("user:a");
        assert!(!guard.is_blocked(&keys));
    }
}

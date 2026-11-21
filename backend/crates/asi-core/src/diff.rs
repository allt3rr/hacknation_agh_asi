//! Porównanie wyników skanów: usługi nowe, znikające i zmienione.
//!
//! Punktem odniesienia jest ostatni znany stan każdego hosta (z przebiegu, w którym
//! ostatnio odpowiedział), a nie po prostu poprzedni skan. Dzięki temu host, który
//! chwilowo nie odpowiadał, po powrocie nie generuje fałszywych "nowych" usług.

use crate::model::Observation;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    New,
    Gone,
    Changed,
    HostInactive,
    HostReturned,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::New => "new",
            ChangeKind::Gone => "gone",
            ChangeKind::Changed => "changed",
            ChangeKind::HostInactive => "host_inactive",
            ChangeKind::HostReturned => "host_returned",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "new" => Some(ChangeKind::New),
            "gone" => Some(ChangeKind::Gone),
            "changed" => Some(ChangeKind::Changed),
            "host_inactive" => Some(ChangeKind::HostInactive),
            "host_returned" => Some(ChangeKind::HostReturned),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub kind: ChangeKind,
    pub key: String,
    pub ip: String,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub before: Option<String>,
    #[serde(default)]
    pub after: Option<String>,
}

impl Change {
    /// Zmiana dotycząca całego hosta (klucz = adres IP).
    pub fn host(kind: ChangeKind, ip: &str, before: Option<String>, after: Option<String>) -> Self {
        Self {
            kind,
            key: ip.to_string(),
            ip: ip.to_string(),
            field: None,
            before,
            after,
        }
    }
}

/// Porównuje usługi.
///
/// Usługa jest oznaczana jako `gone` tylko wtedy, gdy host nadal odpowiada (`live_now`),
/// a portu już nie ma. Brak odpowiedzi całego hosta obsługuje `db::update_host_states`.
pub fn diff(
    baseline: &[Observation],
    current: &[Observation],
    live_now: &HashSet<String>,
) -> Vec<Change> {
    let before: HashMap<String, &Observation> =
        baseline.iter().map(|obs| (obs.key(), obs)).collect();
    let after: HashMap<String, &Observation> = current.iter().map(|obs| (obs.key(), obs)).collect();
    let mut changes = Vec::new();

    for (key, obs) in &after {
        match before.get(key) {
            None => changes.push(Change {
                kind: ChangeKind::New,
                key: key.clone(),
                ip: obs.ip.clone(),
                field: None,
                before: None,
                after: Some(obs.summary()),
            }),
            Some(previous) => changes.extend(changed_fields(key, previous, obs)),
        }
    }

    for (key, obs) in &before {
        let disappeared = !after.contains_key(key) && live_now.contains(&obs.ip);
        if disappeared {
            changes.push(Change {
                kind: ChangeKind::Gone,
                key: key.clone(),
                ip: obs.ip.clone(),
                field: None,
                before: Some(obs.summary()),
                after: None,
            });
        }
    }

    changes.sort_by(|a, b| a.key.cmp(&b.key).then(a.kind.as_str().cmp(b.kind.as_str())));
    changes
}

/// Porównuje tylko pola obecne w obu obserwacjach. Jeśli sonda HTTP nie zadziałała
/// w jednym z przebiegów (np. timeout), pola HTTP są pomijane zamiast zgłaszać szum.
fn changed_fields(key: &str, previous: &Observation, current: &Observation) -> Vec<Change> {
    let old_fields = comparable_fields(previous);
    let new_fields = comparable_fields(current);

    let mut names: Vec<&str> = new_fields.keys().copied().collect();
    names.sort_unstable();

    names
        .into_iter()
        .filter_map(|name| {
            let old_value = old_fields.get(name)?;
            let new_value = &new_fields[name];
            if old_value == new_value {
                return None;
            }
            Some(Change {
                kind: ChangeKind::Changed,
                key: key.to_string(),
                ip: current.ip.clone(),
                field: Some(name.to_string()),
                before: Some(old_value.clone()),
                after: Some(new_value.clone()),
            })
        })
        .collect()
}

fn comparable_fields(obs: &Observation) -> HashMap<&'static str, String> {
    let mut fields = HashMap::new();
    fields.insert("state", obs.state.clone());
    fields.insert("service", obs.service.clone().unwrap_or_default());
    fields.insert("product", obs.product.clone().unwrap_or_default());
    fields.insert("version", obs.version.clone().unwrap_or_default());

    if let Some(http) = &obs.http {
        fields.insert("http_status", http.status.to_string());
        fields.insert("http_title", http.title.clone().unwrap_or_default());
        fields.insert(
            "server",
            http.headers.get("server").cloned().unwrap_or_default(),
        );
        fields.insert(
            "tls_cert",
            http.tls
                .as_ref()
                .map(|tls| tls.sha256.clone())
                .unwrap_or_default(),
        );
        fields.insert("cookies", sorted_cookie_names(obs));
        fields.insert("technologies", sorted_technologies(obs));
    }
    fields
}

fn sorted_cookie_names(obs: &Observation) -> String {
    let Some(http) = &obs.http else {
        return String::new();
    };
    let mut names: Vec<&str> = http.cookie_names().collect();
    names.sort_unstable();
    names.dedup();
    names.join(", ")
}

fn sorted_technologies(obs: &Observation) -> String {
    let mut names: Vec<String> = obs
        .detections
        .iter()
        .map(|detection| match &detection.version {
            Some(version) => format!("{} {version}", detection.name),
            None => detection.name.clone(),
        })
        .collect();
    names.sort();
    names.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(ip: &str, port: u16, product: &str) -> Observation {
        let mut obs = Observation::new(ip.into(), port, "tcp".into());
        obs.product = Some(product.into());
        obs
    }

    #[test]
    fn detects_new_gone_and_changed_services() {
        let baseline = vec![
            service("10.0.0.1", 80, "nginx"),
            service("10.0.0.1", 22, "OpenSSH"),
            service("10.0.0.2", 80, "IIS"),
        ];
        let current = vec![
            service("10.0.0.1", 80, "Apache"),
            service("10.0.0.1", 443, "nginx"),
        ];
        let live: HashSet<String> = ["10.0.0.1".to_string()].into();

        let changes = diff(&baseline, &current, &live);
        let kinds: Vec<(&str, ChangeKind)> =
            changes.iter().map(|c| (c.key.as_str(), c.kind)).collect();

        assert!(kinds.contains(&("10.0.0.1:80/tcp", ChangeKind::Changed)));
        assert!(kinds.contains(&("10.0.0.1:443/tcp", ChangeKind::New)));
        assert!(kinds.contains(&("10.0.0.1:22/tcp", ChangeKind::Gone)));
        // 10.0.0.2 nie odpowiedział, więc jego usługi nie są oznaczane jako "gone".
        assert!(!changes.iter().any(|c| c.ip == "10.0.0.2"));
    }

    #[test]
    fn missing_http_in_one_run_is_not_a_change() {
        let mut before = service("10.0.0.1", 80, "nginx");
        before.http = Some(crate::model::HttpInfo {
            status: 200,
            title: Some("A".into()),
            ..Default::default()
        });
        let after = service("10.0.0.1", 80, "nginx");
        let live: HashSet<String> = ["10.0.0.1".to_string()].into();
        assert!(diff(&[before.clone()], &[after], &live).is_empty());

        let mut changed = before.clone();
        changed.http.as_mut().unwrap().title = Some("B".into());
        let c = diff(&[before], &[changed], &live);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].field.as_deref(), Some("http_title"));
    }
}

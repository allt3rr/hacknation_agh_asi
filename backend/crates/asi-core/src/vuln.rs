//! Podatności: identyfikacja usługi (CPE), klasyfikacja CVSS → severity i typy wyniku.

use crate::model::Observation;
use serde::{Deserialize, Serialize};

/// Poziomy dowodu, od najmocniejszego: potwierdzona sondą → dokładna wersja → wersja pakietu
/// dystrybucji (poprawka mogła zostać przeniesiona wstecz) → podatna tylko w określonej konfiguracji.
pub const EVIDENCE_CONFIRMED: &str = "confirmed";
pub const EVIDENCE_VERSION_MATCH: &str = "version_match";
pub const EVIDENCE_BACKPORT: &str = "version_backport";
pub const EVIDENCE_CONDITIONAL: &str = "version_conditional";

/// CVE z bazy (NVD) przed dopasowaniem do usługi.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveInfo {
    pub id: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub description: String,
    pub published: Option<String>,
    /// Inne komponenty (`dostawca:produkt`), bez których CVE nie dotyczy usługi (konfiguracja AND w NVD).
    #[serde(default)]
    pub requires: Vec<String>,
}

/// Podatność usługi w przebiegu.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub ip: String,
    pub port: u16,
    pub proto: String,
    pub cve_id: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub severity: String,
    /// Jeden z `EVIDENCE_*`.
    pub evidence: String,
    pub component: String,
    pub version: String,
    pub description: String,
    pub published: Option<String>,
}

impl Vulnerability {
    /// Klucz usługi w formacie `Observation::key`, do łączenia z korektami analityka.
    pub fn service_key(&self) -> String {
        format!("{}:{}/{}", self.ip, self.port, self.proto)
    }
}

/// Severity z wyniku CVSS v3 (progi NVD). Brak oceny = `Info`.
pub fn severity_from_cvss(score: Option<f64>) -> &'static str {
    match score {
        Some(s) if s >= 9.0 => "Critical",
        Some(s) if s >= 7.0 => "High",
        Some(s) if s >= 4.0 => "Medium",
        Some(s) if s > 0.0 => "Low",
        _ => "Info",
    }
}

/// Usługa gotowa do korelacji: CPE 2.3 oraz nazwa i wersja komponentu.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceId {
    pub cpe: String,
    pub product: String,
    pub version: String,
    /// Pakiet dystrybucji (np. „8.9p1 Ubuntu 3ubuntu0.6”): wersja upstream nie mówi o poprawkach.
    pub backport: bool,
}

/// Nazwy dostawców z nmap, które NVD zastąpiło innymi (stare CPE nie trafiają w konfiguracje CVE).
const VENDOR_RENAMES: &[((&str, &str), &str)] = &[
    (("igor_sysoev", "nginx"), "f5"),
    (("nginx", "nginx"), "f5"),
    (("mysql", "mysql"), "oracle"),
];

/// Ślady pakietu dystrybucji w wersji lub dodatkowym opisie usługi z nmap.
const DISTRO_MARKERS: &[&str] = &[
    "ubuntu",
    "debian",
    "raspbian",
    "centos",
    "red hat",
    "rhel",
    ".el",
    "fedora",
    "suse",
    "alpine",
    "amzn",
    "amazon linux",
];

fn is_distro_build(o: &Observation) -> bool {
    [o.version.as_deref(), o.extra_info.as_deref()]
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .any(|s| DISTRO_MARKERS.iter().any(|m| s.contains(m)))
}

/// CPE 2.3 z wersją. OpenSSH: „8.9p1” → wersja „8.9” i update „p1”, jak w słowniku NVD.
fn cpe23(vendor: &str, product: &str, version: &str) -> String {
    let vendor = VENDOR_RENAMES
        .iter()
        .find(|((v, p), _)| *v == vendor && *p == product)
        .map_or(vendor, |(_, to)| to);
    let (ver, update) = match version.split_once('p') {
        Some((v, u))
            if product == "openssh"
                && !v.is_empty()
                && u.chars().all(|c| c.is_ascii_digit())
                && !u.is_empty() =>
        {
            (v, format!("p{u}"))
        }
        _ => (version, "*".to_string()),
    };
    format!("cpe:2.3:a:{vendor}:{product}:{ver}:{update}:*:*:*:*:*:*")
}

/// (fragment nazwy produktu małymi literami, dostawca, produkt w CPE).
const ALIASES: &[(&str, &str, &str)] = &[
    ("apache httpd", "apache", "http_server"),
    ("apache tomcat", "apache", "tomcat"),
    ("tomcat", "apache", "tomcat"),
    ("nginx", "f5", "nginx"),
    ("mariadb", "mariadb", "mariadb"),
    ("mysql", "oracle", "mysql"),
    ("openssh", "openbsd", "openssh"),
    ("grafana", "grafana", "grafana"),
    ("wordpress", "wordpress", "wordpress"),
    ("postgresql", "postgresql", "postgresql"),
    ("proftpd", "proftpd", "proftpd"),
    ("vsftpd", "vsftpd_project", "vsftpd"),
    ("redis", "redis", "redis"),
    ("lighttpd", "lighttpd", "lighttpd"),
    (
        "microsoft iis",
        "microsoft",
        "internet_information_services",
    ),
    ("php", "php", "php"),
];

/// Pierwszy token wersji, np. "8.9p1 Ubuntu 3" → "8.9p1". Pusty wynik = brak wersji.
fn clean_version(v: &str) -> String {
    let token = v.split_whitespace().next().unwrap_or("");
    if token.starts_with(|c: char| c.is_ascii_digit())
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_+".contains(c))
    {
        token.to_ascii_lowercase()
    } else {
        String::new()
    }
}

fn service(vendor: &str, product: &str, version: String, backport: bool) -> ServiceId {
    ServiceId {
        cpe: cpe23(vendor, product, &version),
        product: product.into(),
        version,
        backport,
    }
}

fn from_alias(name: &str, version: &str, backport: bool) -> Option<ServiceId> {
    let version = clean_version(version);
    if version.is_empty() {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    let (_, vendor, product) = ALIASES.iter().find(|(frag, _, _)| lower.contains(frag))?;
    Some(service(vendor, product, version, backport))
}

/// CPE 2.2 URI z nmap (`cpe:/a:apache:http_server:2.4.49`) → CPE 2.3 z wersją. Gdy CPE nie ma
/// wersji, bierze wersję usługi z nmap (dostawca i produkt z CPE są pewniejsze niż aliasy).
/// `None`, gdy to nie jest aplikacja (`a`) albo wersji nie ma nigdzie.
fn from_nmap_cpe(cpe: &str, service_version: Option<&str>, backport: bool) -> Option<ServiceId> {
    let rest = cpe.strip_prefix("cpe:/a:")?;
    let mut parts = rest.split(':');
    let (vendor, product) = (parts.next()?, parts.next()?);
    let mut version = clean_version(parts.next().unwrap_or(""));
    if version.is_empty() {
        version = clean_version(service_version.unwrap_or(""));
    }
    if vendor.is_empty() || product.is_empty() || version.is_empty() {
        return None;
    }
    Some(service(vendor, product, version, backport))
}

/// Co działa pod tym portem: CPE z nmap → produkt i wersja z nmap → technologia z wersją
/// (sygnatury HTTP, np. wersja CMS z meta generatora).
pub fn identify(o: &Observation) -> Option<ServiceId> {
    let backport = is_distro_build(o);
    o.cpe
        .iter()
        .find_map(|c| from_nmap_cpe(c, o.version.as_deref(), backport))
        .or_else(|| {
            o.product
                .as_deref()
                .zip(o.version.as_deref())
                .and_then(|(p, v)| from_alias(p, v, backport))
        })
        .or_else(|| {
            o.detections.iter().find_map(|d| {
                d.version
                    .as_deref()
                    .and_then(|v| from_alias(&d.name, v, false))
            })
        })
}

/// Poziom dowodu korelacji wersji: warunkowa konfiguracja jest najsłabsza, potem pakiet dystrybucji.
pub fn version_evidence(id: &ServiceId, cve: &CveInfo) -> &'static str {
    if !cve.requires.is_empty() {
        EVIDENCE_CONDITIONAL
    } else if id.backport {
        EVIDENCE_BACKPORT
    } else {
        EVIDENCE_VERSION_MATCH
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Detection;

    #[test]
    fn severity_thresholds() {
        let cases = [
            (None, "Info"),
            (Some(0.0), "Info"),
            (Some(0.1), "Low"),
            (Some(3.9), "Low"),
            (Some(4.0), "Medium"),
            (Some(6.9), "Medium"),
            (Some(7.0), "High"),
            (Some(8.9), "High"),
            (Some(9.0), "Critical"),
            (Some(10.0), "Critical"),
        ];
        for (score, want) in cases {
            assert_eq!(severity_from_cvss(score), want, "{score:?}");
        }
    }

    fn obs() -> Observation {
        Observation::new("10.0.0.1".into(), 80, "tcp".into())
    }

    #[test]
    fn identify_prefers_nmap_cpe() {
        let mut o = obs();
        o.cpe = vec![
            "cpe:/o:linux:linux_kernel".into(),
            "cpe:/a:apache:http_server:2.4.49".into(),
        ];
        o.product = Some("nginx".into());
        o.version = Some("1.24.0".into());
        let id = identify(&o).unwrap();
        assert_eq!(id.cpe, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
        assert_eq!(id.version, "2.4.49");
    }

    #[test]
    fn identify_from_product_and_detection() {
        let mut o = obs();
        o.product = Some("OpenSSH".into());
        o.version = Some("8.9p1 Ubuntu 3".into());
        let id = identify(&o).unwrap();
        assert_eq!(id.cpe, "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*");
        assert_eq!(id.version, "8.9p1");
        assert!(id.backport, "pakiet Ubuntu");

        let mut o = obs();
        o.detections.push(Detection {
            signature_id: "wp".into(),
            name: "WordPress".into(),
            category: "cms".into(),
            version: Some("6.4.1".into()),
            confidence: 90,
            evidence: vec![],
        });
        assert_eq!(
            identify(&o).unwrap().cpe,
            "cpe:2.3:a:wordpress:wordpress:6.4.1:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn nmap_cpe_without_version_uses_service_version_and_current_vendor() {
        let mut o = obs();
        o.cpe = vec!["cpe:/a:igor_sysoev:nginx".into()];
        o.product = Some("nginx".into());
        o.version = Some("1.18.0".into());
        o.extra_info = Some("Ubuntu".into());
        let id = identify(&o).unwrap();
        assert_eq!(id.cpe, "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*");
        assert!(id.backport);

        let mut o = obs();
        o.cpe = vec!["cpe:/a:apache:http_server:2.4.49".into()];
        assert!(!identify(&o).unwrap().backport, "wersja upstream");
    }

    #[test]
    fn evidence_levels() {
        let mut id = ServiceId {
            cpe: "x".into(),
            product: "http_server".into(),
            version: "2.4.49".into(),
            backport: false,
        };
        let mut cve = CveInfo {
            id: "CVE-1".into(),
            cvss_score: None,
            cvss_vector: None,
            description: String::new(),
            published: None,
            requires: vec![],
        };
        assert_eq!(version_evidence(&id, &cve), EVIDENCE_VERSION_MATCH);
        id.backport = true;
        assert_eq!(version_evidence(&id, &cve), EVIDENCE_BACKPORT);
        cve.requires = vec!["microsoft:windows".into()];
        assert_eq!(version_evidence(&id, &cve), EVIDENCE_CONDITIONAL);
    }

    #[test]
    fn identify_without_version_is_none() {
        let mut o = obs();
        o.product = Some("nginx".into());
        assert!(identify(&o).is_none());
        o.cpe = vec!["cpe:/a:f5:nginx".into()];
        assert!(identify(&o).is_none());
        o.version = Some("unknown".into());
        assert!(identify(&o).is_none());
    }
}

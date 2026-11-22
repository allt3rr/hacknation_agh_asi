//! Zatwierdzony zakres ruchu. Każde połączenie HTTP przechodzi przez `Scope::check`.

use anyhow::{bail, Context, Result};
use asi_core::targets::{Target, TargetKind};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use url::{Host, Url};

/// Zbiór portów z zapisu `22,80,443,8000-8100`.
#[derive(Debug, Clone, Default)]
pub struct PortSet(Vec<(u16, u16)>);

impl PortSet {
    pub fn parse(spec: &str) -> Result<Self> {
        let mut ranges = Vec::new();
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (a, b) = match part.split_once('-') {
                Some((a, b)) => (a, b),
                None => (part, part),
            };
            let a: u16 = a.trim().parse().with_context(|| format!("port {part:?}"))?;
            let b: u16 = b.trim().parse().with_context(|| format!("port {part:?}"))?;
            if a == 0 || a > b {
                bail!("niepoprawny zakres portów {part:?}");
            }
            ranges.push((a, b));
        }
        if ranges.is_empty() {
            bail!("pusta lista portów");
        }
        Ok(Self(ranges))
    }

    pub fn contains(&self, port: u16) -> bool {
        self.0.iter().any(|&(a, b)| (a..=b).contains(&port))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Scope {
    nets: Vec<IpNet>,
    domains: HashSet<String>,
    /// Adresy, na które nmap rozwiązał domeny-cele w tym przebiegu.
    resolved: HashSet<IpAddr>,
    allowed_ports: Option<PortSet>,
    /// Porty otwarte wykryte w tym przebiegu.
    open: HashMap<IpAddr, HashSet<u16>>,
}

impl Scope {
    pub fn new(targets: &[Target], allowed_ports: Option<PortSet>) -> Self {
        let mut scope = Self {
            allowed_ports,
            ..Default::default()
        };
        for t in targets {
            match t.kind {
                TargetKind::Ip | TargetKind::Cidr => {
                    if let Ok(net) = t.value.parse::<IpNet>() {
                        scope.nets.push(net);
                    } else if let Ok(ip) = t.value.parse::<IpAddr>() {
                        scope.nets.push(IpNet::from(ip));
                    }
                }
                TargetKind::Domain => {
                    scope.domains.insert(t.value.to_ascii_lowercase());
                }
            }
        }
        scope
    }

    pub fn add_resolved(&mut self, ip: IpAddr) {
        self.resolved.insert(ip);
    }

    pub fn add_open_port(&mut self, ip: IpAddr, port: u16) {
        self.open.entry(ip).or_default().insert(port);
    }

    pub fn is_domain_target(&self, name: &str) -> bool {
        self.domains.contains(&name.to_ascii_lowercase())
    }

    pub fn ip_in_scope(&self, ip: IpAddr) -> bool {
        self.resolved.contains(&ip) || self.nets.iter().any(|n| n.contains(&ip))
    }

    /// Czy wolno połączyć się z tym URL-em: schemat http/https, host w celach, port dozwolony lub wykryty.
    pub fn check(&self, url: &Url) -> Result<()> {
        if !matches!(url.scheme(), "http" | "https") {
            bail!("schemat {} poza zakresem", url.scheme());
        }
        let port = url.port_or_known_default().context("brak portu")?;
        let ip = match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip),
            // Połączenia wykonujemy wyłącznie na sprawdzony adres IP.
            // Nazwa z przekierowania wymagałaby ponownego rozwiązania DNS.
            _ => bail!("host {:?} poza zakresem", url.host_str()),
        };
        if !self.ip_in_scope(ip) {
            bail!("adres {ip} poza zakresem");
        }
        let detected = self.open.get(&ip).is_some_and(|p| p.contains(&port));
        let allowed = self
            .allowed_ports
            .as_ref()
            .is_some_and(|p| p.contains(port));
        if !(detected || allowed) {
            bail!("port {port} na {ip} poza zakresem");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asi_core::targets::classify;

    fn scope() -> Scope {
        let targets: Vec<Target> = ["10.0.0.0/24", "192.168.1.5", "intranet.agh.edu.pl"]
            .iter()
            .map(|t| classify(t).unwrap())
            .collect();
        let mut s = Scope::new(&targets, Some(PortSet::parse("80,443,8000-8010").unwrap()));
        s.add_open_port("10.0.0.7".parse().unwrap(), 9443);
        s.add_resolved("172.16.0.1".parse().unwrap());
        s
    }

    fn ok(s: &Scope, url: &str) -> bool {
        s.check(&Url::parse(url).unwrap()).is_ok()
    }

    #[test]
    fn checks_scheme_host_and_port() {
        let s = scope();
        assert!(ok(&s, "http://10.0.0.7/"));
        assert!(ok(&s, "https://10.0.0.7:9443/x"));
        assert!(ok(&s, "http://192.168.1.5:8005/"));
        assert!(ok(&s, "https://172.16.0.1/"));
        assert!(
            !ok(&s, "https://Intranet.AGH.edu.pl/"),
            "połączenie wymaga sprawdzonego IP"
        );

        assert!(
            !ok(&s, "http://10.0.0.8:9443/"),
            "port wykryty tylko na innym hoście"
        );
        assert!(!ok(&s, "http://10.0.1.1/"), "adres poza CIDR");
        assert!(!ok(&s, "http://intranet.agh.edu.pl:9443/"));
        assert!(!ok(&s, "http://example.com/"), "obca domena");
        assert!(!ok(&s, "ftp://10.0.0.7/"), "schemat");
        assert!(!ok(&s, "http://10.0.0.7:22/"), "port niedozwolony");
    }

    #[test]
    fn parses_port_sets() {
        let p = PortSet::parse("22, 80,8000-8002").unwrap();
        assert!(p.contains(22) && p.contains(8001) && !p.contains(8003));
        assert!(PortSet::parse("0").is_err());
        assert!(PortSet::parse("90-80").is_err());
        assert!(PortSet::parse("http").is_err());
    }
}

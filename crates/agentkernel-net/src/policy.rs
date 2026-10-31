use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Represents an egress filtering policy for sandboxed execution environments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressPolicy {
    pub allow_all: bool,
    pub allowed_domains: Vec<String>,
    pub blocked_cidrs: Vec<String>,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allow_all: false,
            allowed_domains: vec![
                "registry.npmjs.org".into(),
                "pypi.org".into(),
                "files.pythonhosted.org".into(),
                "crates.io".into(),
                "static.crates.io".into(),
                "github.com".into(),
            ],
            blocked_cidrs: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "169.254.169.254/32".into(),
            ],
        }
    }
}

impl EgressPolicy {
    /// Checks if a domain is allowed under the current policy.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        if self.allow_all {
            return true;
        }

        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();

        for rule in &self.allowed_domains {
            let pattern = rule.trim_end_matches('.').to_ascii_lowercase();

            // Direct match
            if normalized == pattern {
                return true;
            }

            // Wildcard prefix: *.example.com
            if pattern.starts_with("*.") {
                let suffix = &pattern[2..];
                if normalized == suffix || normalized.ends_with(&format!(".{}", suffix)) {
                    return true;
                }
            } else {
                // Subdomain matching: api.github.com matches github.com
                if normalized.ends_with(&format!(".{}", pattern)) {
                    return true;
                }
            }
        }

        false
    }

    /// Checks if an IP address falls within any blocked CIDRs.
    pub fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        for cidr_str in &self.blocked_cidrs {
            if let Ok(cidr) = CidrBlock::parse(cidr_str) {
                if cidr.contains(ip) {
                    return true;
                }
            }
        }
        false
    }

    /// Dynamically appends a new domain to the allowed domains list if not already present.
    pub fn allow_domain(&mut self, domain: &str) {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !self
            .allowed_domains
            .iter()
            .any(|d| d.trim_end_matches('.').to_ascii_lowercase() == normalized)
        {
            self.allowed_domains.push(normalized);
        }
    }
}

/// CIDR representation supporting IPv4 and IPv6 subnet calculations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrBlock {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl CidrBlock {
    /// Parses a CIDR notation string (e.g. "10.0.0.0/8" or "169.254.169.254/32").
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.is_empty() || parts.len() > 2 {
            return Err(format!("Invalid CIDR format: {}", s));
        }

        let ip_str = parts[0].trim();
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|e| format!("Invalid IP address in CIDR {}: {}", s, e))?;

        match ip {
            IpAddr::V4(v4) => {
                let prefix: u32 = if parts.len() == 2 {
                    parts[1]
                        .trim()
                        .parse()
                        .map_err(|_| format!("Invalid prefix in {}", s))?
                } else {
                    32
                };

                if prefix > 32 {
                    return Err(format!("IPv4 prefix out of range: {}", prefix));
                }

                let mask = if prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix)
                };

                let network = u32::from(v4) & mask;
                Ok(CidrBlock::V4 { network, mask })
            }
            IpAddr::V6(v6) => {
                let prefix: u32 = if parts.len() == 2 {
                    parts[1]
                        .trim()
                        .parse()
                        .map_err(|_| format!("Invalid prefix in {}", s))?
                } else {
                    128
                };

                if prefix > 128 {
                    return Err(format!("IPv6 prefix out of range: {}", prefix));
                }

                let mask = if prefix == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix)
                };

                let network = u128::from(v6) & mask;
                Ok(CidrBlock::V6 { network, mask })
            }
        }
    }

    /// Tests if an IP address is contained within this CIDR block.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (CidrBlock::V4 { network, mask }, IpAddr::V4(v4)) => {
                let ip_u32 = u32::from(v4);
                (ip_u32 & mask) == *network
            }
            (CidrBlock::V6 { network, mask }, IpAddr::V6(v6)) => {
                let ip_u128 = u128::from(v6);
                (ip_u128 & mask) == *network
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_allowlist() {
        let policy = EgressPolicy::default();

        assert!(policy.is_domain_allowed("github.com"));
        assert!(policy.is_domain_allowed("api.github.com"));
        assert!(policy.is_domain_allowed("codeload.github.com"));
        assert!(policy.is_domain_allowed("registry.npmjs.org"));
        assert!(policy.is_domain_allowed("crates.io"));
        assert!(policy.is_domain_allowed("static.crates.io"));
        assert!(policy.is_domain_allowed("pypi.org"));
        assert!(policy.is_domain_allowed("files.pythonhosted.org"));

        // Uppercase and trailing dot
        assert!(policy.is_domain_allowed("GITHUB.COM."));
        assert!(policy.is_domain_allowed("API.GITHUB.COM"));

        // Disallowed domains
        assert!(!policy.is_domain_allowed("evil.com"));
        assert!(!policy.is_domain_allowed("notgithub.com"));
        assert!(!policy.is_domain_allowed("fake-crates.io"));
        assert!(!policy.is_domain_allowed("localhost"));
    }

    #[test]
    fn test_allow_all_policy() {
        let policy = EgressPolicy {
            allow_all: true,
            allowed_domains: vec![],
            blocked_cidrs: vec![],
        };

        assert!(policy.is_domain_allowed("anything.com"));
        assert!(policy.is_domain_allowed("evil.org"));
    }

    #[test]
    fn test_cidr_blocking() {
        let policy = EgressPolicy::default();

        // Private 10.0.0.0/8
        assert!(policy.is_ip_blocked("10.0.0.1".parse().unwrap()));
        assert!(policy.is_ip_blocked("10.254.12.3".parse().unwrap()));

        // Private 172.16.0.0/12
        assert!(policy.is_ip_blocked("172.16.0.1".parse().unwrap()));
        assert!(policy.is_ip_blocked("172.31.255.255".parse().unwrap()));
        assert!(!policy.is_ip_blocked("172.32.0.1".parse().unwrap()));

        // Private 192.168.0.0/16
        assert!(policy.is_ip_blocked("192.168.1.1".parse().unwrap()));
        assert!(policy.is_ip_blocked("192.168.254.254".parse().unwrap()));

        // Cloud metadata 169.254.169.254/32
        assert!(policy.is_ip_blocked("169.254.169.254".parse().unwrap()));
        assert!(!policy.is_ip_blocked("169.254.169.253".parse().unwrap()));

        // Public IPs should not be blocked
        assert!(!policy.is_ip_blocked("140.82.121.4".parse().unwrap())); // GitHub
        assert!(!policy.is_ip_blocked("1.1.1.1".parse().unwrap())); // Cloudflare
        assert!(!policy.is_ip_blocked("8.8.8.8".parse().unwrap())); // Google
    }

    #[test]
    fn test_dynamic_allow_domain() {
        let mut policy = EgressPolicy::default();
        assert!(!policy.is_domain_allowed("custom-api.anthropic.com"));

        policy.allow_domain("custom-api.anthropic.com");
        assert!(policy.is_domain_allowed("custom-api.anthropic.com"));

        // Deduplication
        let count_before = policy.allowed_domains.len();
        policy.allow_domain("custom-api.anthropic.com.");
        assert_eq!(policy.allowed_domains.len(), count_before);
    }
}

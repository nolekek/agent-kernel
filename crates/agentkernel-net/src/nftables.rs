use crate::policy::EgressPolicy;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

/// Dynamic nftables allowlist and egress firewall ruleset generator.
#[derive(Debug, Clone)]
pub struct NftablesGenerator {
    table_name: String,
    policy: EgressPolicy,
    allowed_v4: Arc<RwLock<HashSet<Ipv4Addr>>>,
    allowed_v6: Arc<RwLock<HashSet<Ipv6Addr>>>,
}

impl NftablesGenerator {
    /// Creates a new NftablesGenerator for a given table name and base policy.
    pub fn new(table_name: &str, policy: EgressPolicy) -> Self {
        Self {
            table_name: table_name.to_string(),
            policy,
            allowed_v4: Arc::new(RwLock::new(HashSet::new())),
            allowed_v6: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Dynamically adds an IP to the allowlist set.
    /// Returns the corresponding nft command if the IP was not already present.
    pub fn add_ip(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) => {
                let mut set = self.allowed_v4.write().unwrap();
                if set.insert(v4) {
                    Some(format!(
                        "nft add element inet {} allowed_ips {{ {} }}",
                        self.table_name, v4
                    ))
                } else {
                    None
                }
            }
            IpAddr::V6(v6) => {
                let mut set = self.allowed_v6.write().unwrap();
                if set.insert(v6) {
                    Some(format!(
                        "nft add element inet {} allowed_ipv6 {{ {} }}",
                        self.table_name, v6
                    ))
                } else {
                    None
                }
            }
        }
    }

    /// Checks if an IP is currently in the dynamic allowlist.
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.allowed_v4.read().unwrap().contains(v4),
            IpAddr::V6(v6) => self.allowed_v6.read().unwrap().contains(v6),
        }
    }

    /// Returns a list of all currently allowed IPs.
    pub fn get_allowed_ips(&self) -> Vec<IpAddr> {
        let mut list = Vec::new();
        for v4 in self.allowed_v4.read().unwrap().iter() {
            list.push(IpAddr::V4(*v4));
        }
        for v6 in self.allowed_v6.read().unwrap().iter() {
            list.push(IpAddr::V6(*v6));
        }
        list
    }

    /// Renders the complete, self-contained nftables ruleset string.
    pub fn render_ruleset(&self) -> String {
        let v4_set = self.allowed_v4.read().unwrap();
        let v6_set = self.allowed_v6.read().unwrap();

        let v4_elements: Vec<String> = v4_set.iter().map(|ip| ip.to_string()).collect();
        let v6_elements: Vec<String> = v6_set.iter().map(|ip| ip.to_string()).collect();

        let blocked_v4_list = self
            .policy
            .blocked_cidrs
            .iter()
            .filter(|cidr| !cidr.contains(':'))
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        let mut ruleset = String::new();
        ruleset.push_str(&format!("table inet {} {{\n", self.table_name));

        // Sets
        ruleset.push_str("    set allowed_ips {\n");
        ruleset.push_str("        type ipv4_addr\n");
        ruleset.push_str("        flags interval\n");
        if !v4_elements.is_empty() {
            ruleset.push_str(&format!(
                "        elements = {{ {} }}\n",
                v4_elements.join(", ")
            ));
        }
        ruleset.push_str("    }\n\n");

        ruleset.push_str("    set allowed_ipv6 {\n");
        ruleset.push_str("        type ipv6_addr\n");
        ruleset.push_str("        flags interval\n");
        if !v6_elements.is_empty() {
            ruleset.push_str(&format!(
                "        elements = {{ {} }}\n",
                v6_elements.join(", ")
            ));
        }
        ruleset.push_str("    }\n\n");

        // Egress Filter Chain
        ruleset.push_str("    chain egress {\n");
        ruleset.push_str("        type filter hook output priority 0; policy drop;\n\n");
        ruleset.push_str("        # Allow loopback interface\n");
        ruleset.push_str("        iif \"lo\" accept\n");
        ruleset.push_str("        oif \"lo\" accept\n\n");
        ruleset.push_str("        # Allow DNS queries to Smart DNS Proxy\n");
        ruleset.push_str("        udp dport 53 accept\n");
        ruleset.push_str("        tcp dport 53 accept\n\n");
        ruleset.push_str("        # Allow established and related connections\n");
        ruleset.push_str("        ct state established,related accept\n\n");

        if !blocked_v4_list.is_empty() {
            ruleset.push_str("        # Drop cloud metadata and private RFC1918 CIDRs\n");
            ruleset.push_str(&format!(
                "        ip daddr {{ {} }} drop\n\n",
                blocked_v4_list
            ));
        }

        ruleset.push_str("        # Dynamic allowlist accepted\n");
        ruleset.push_str("        ip daddr @allowed_ips accept\n");
        ruleset.push_str("        ip6 daddr @allowed_ipv6 accept\n");
        ruleset.push_str("    }\n");
        ruleset.push_str("}\n");

        ruleset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nftables_render() {
        let generator = NftablesGenerator::new("agentkernel_test", EgressPolicy::default());

        let initial_ruleset = generator.render_ruleset();
        assert!(initial_ruleset.contains("table inet agentkernel_test"));
        assert!(initial_ruleset.contains("policy drop;"));
        assert!(initial_ruleset.contains("169.254.169.254/32"));
        assert!(initial_ruleset.contains("ip daddr @allowed_ips accept"));

        // Add dynamic IP
        let ip: IpAddr = "140.82.121.4".parse().unwrap();
        let cmd = generator.add_ip(ip);
        assert!(cmd.is_some());
        assert_eq!(
            cmd.unwrap(),
            "nft add element inet agentkernel_test allowed_ips { 140.82.121.4 }"
        );

        // Second addition is deduplicated
        assert!(generator.add_ip(ip).is_none());
        assert!(generator.contains_ip(&ip));

        // Updated ruleset includes element
        let updated = generator.render_ruleset();
        assert!(updated.contains("elements = { 140.82.121.4 }"));
    }
}

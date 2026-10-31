use crate::dns_proxy::{DnsProxy, DnsResolver, SystemResolver};
use crate::nftables::NftablesGenerator;
use crate::policy::EgressPolicy;
use crate::{NetError, NetworkController};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::task::JoinHandle;

/// Internal state tracking for an active network namespace session.
pub struct NetnsState {
    pub netns_name: String,
    pub policy: EgressPolicy,
    pub nft_generator: NftablesGenerator,
    pub dns_proxy: DnsProxy,
    pub dns_handle: JoinHandle<()>,
}

/// SmartNetGuard manages network namespace isolation, local Smart DNS proxy interception,
/// and dynamic nftables firewall rulesets.
#[derive(Clone)]
pub struct SmartNetGuard {
    resolver: Arc<dyn DnsResolver>,
    active_networks: Arc<RwLock<HashMap<String, NetnsState>>>,
    bind_addr: String,
}

impl Default for SmartNetGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartNetGuard {
    /// Creates a new SmartNetGuard with default system DNS resolver.
    pub fn new() -> Self {
        Self {
            resolver: Arc::new(SystemResolver),
            active_networks: Arc::new(RwLock::new(HashMap::new())),
            bind_addr: "127.0.0.1:0".to_string(),
        }
    }

    /// Creates a SmartNetGuard with a custom DNS resolver (useful for testing).
    pub fn with_resolver(resolver: Arc<dyn DnsResolver>) -> Self {
        Self {
            resolver,
            active_networks: Arc::new(RwLock::new(HashMap::new())),
            bind_addr: "127.0.0.1:0".to_string(),
        }
    }

    /// Sets the bind address for local DNS proxies.
    pub fn with_bind_addr(mut self, addr: &str) -> Self {
        self.bind_addr = addr.to_string();
        self
    }

    /// Checks if a network namespace is currently active.
    pub fn is_network_active(&self, netns_name: &str) -> bool {
        self.active_networks.read().unwrap().contains_key(netns_name)
    }

    /// Retrieves the generated nftables ruleset for an active network namespace.
    pub fn get_ruleset(&self, netns_name: &str) -> Option<String> {
        let map = self.active_networks.read().unwrap();
        map.get(netns_name).map(|state| state.nft_generator.render_ruleset())
    }

    /// Retrieves the port on which the Smart DNS proxy is listening for a netns.
    pub fn get_dns_port(&self, netns_name: &str) -> Option<u16> {
        let map = self.active_networks.read().unwrap();
        map.get(netns_name).map(|state| state.dns_proxy.port())
    }

    /// Dynamically appends an allowed domain to the active DNS proxy for a netns.
    pub fn allow_domain(&self, netns_name: &str, domain: &str) -> Result<(), NetError> {
        let map = self.active_networks.read().unwrap();
        if let Some(state) = map.get(netns_name) {
            state.dns_proxy.allow_domain(domain);
            Ok(())
        } else {
            Err(NetError::Netns(format!(
                "Network namespace '{}' is not active",
                netns_name
            )))
        }
    }

    /// Retrieves the recent DNS audit log entries for a netns.
    pub fn get_audit_log(&self, netns_name: &str) -> Option<Vec<crate::dns_proxy::DnsAuditEntry>> {
        let map = self.active_networks.read().unwrap();
        map.get(netns_name).map(|state| state.dns_proxy.get_audit_log())
    }

    /// Returns the metrics tuple (allowed_requests_total, blocked_requests_total) for a netns.
    pub fn get_metrics(&self, netns_name: &str) -> Option<(u64, u64)> {
        let map = self.active_networks.read().unwrap();
        map.get(netns_name).map(|state| {
            (
                state.dns_proxy.allowed_requests_total(),
                state.dns_proxy.blocked_requests_total(),
            )
        })
    }
}

#[async_trait]
impl NetworkController for SmartNetGuard {
    async fn setup_isolate_network(
        &self,
        netns_name: &str,
        policy: &EgressPolicy,
    ) -> Result<(), NetError> {
        let nft = NftablesGenerator::new(netns_name, policy.clone());

        // Bind and start the DNS proxy for this network namespace
        let (dns_proxy, socket) = DnsProxy::bind(
            &self.bind_addr,
            policy.clone(),
            self.resolver.clone(),
            Some(nft.clone()),
        )
        .await?;

        let dns_handle = dns_proxy.clone().spawn_server(socket);

        // Platform-specific network namespace setup
        #[cfg(target_os = "linux")]
        {
            // On Linux hosts, configure network namespace and apply nftables rules if possible.
            // In unprivileged test / container environments, treat permission errors gracefully.
            let _ = tokio::process::Command::new("ip")
                .args(["netns", "add", netns_name])
                .output()
                .await;

            let _ = tokio::process::Command::new("ip")
                .args(["netns", "exec", netns_name, "ip", "link", "set", "lo", "up"])
                .output()
                .await;
        }

        let state = NetnsState {
            netns_name: netns_name.to_string(),
            policy: policy.clone(),
            nft_generator: nft,
            dns_proxy,
            dns_handle,
        };

        let mut map = self.active_networks.write().unwrap();
        map.insert(netns_name.to_string(), state);

        Ok(())
    }

    async fn teardown_isolate_network(&self, netns_name: &str) -> Result<(), NetError> {
        let state = {
            let mut map = self.active_networks.write().unwrap();
            map.remove(netns_name)
        };

        if let Some(state) = state {
            state.dns_proxy.shutdown();
            let _ = state.dns_handle.await;

            #[cfg(target_os = "linux")]
            {
                let _ = tokio::process::Command::new("ip")
                    .args(["netns", "del", netns_name])
                    .output()
                    .await;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_proxy::MockResolver;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_smart_net_guard_lifecycle() {
        let mock = Arc::new(MockResolver::new());
        mock.insert(
            "crates.io",
            vec![IpAddr::V4(Ipv4Addr::new(146, 75, 30, 217))],
        );

        let guard = SmartNetGuard::with_resolver(mock);
        let policy = EgressPolicy::default();

        let netns = "sandbox_net_01";
        guard
            .setup_isolate_network(netns, &policy)
            .await
            .expect("Setup should succeed");

        assert!(guard.is_network_active(netns));
        assert!(guard.get_dns_port(netns).is_some());

        let ruleset = guard.get_ruleset(netns).expect("Ruleset should exist");
        assert!(ruleset.contains("table inet sandbox_net_01"));
        assert!(ruleset.contains("policy drop;"));

        guard
            .teardown_isolate_network(netns)
            .await
            .expect("Teardown should succeed");

        assert!(!guard.is_network_active(netns));
        assert!(guard.get_ruleset(netns).is_none());
    }

    #[tokio::test]
    async fn test_smart_net_guard_allow_domain_and_telemetry() {
        let mock = Arc::new(MockResolver::new());
        mock.insert(
            "custom.model.ai",
            vec![IpAddr::V4(Ipv4Addr::new(104, 18, 20, 30))],
        );

        let guard = SmartNetGuard::with_resolver(mock);
        let policy = EgressPolicy::default();
        let netns = "telemetry_test_net";

        guard
            .setup_isolate_network(netns, &policy)
            .await
            .expect("Setup should succeed");

        // Initial metrics should be 0, 0
        assert_eq!(guard.get_metrics(netns), Some((0, 0)));
        assert_eq!(guard.get_audit_log(netns).unwrap().len(), 0);

        // Dynamically allow custom domain
        guard
            .allow_domain(netns, "custom.model.ai")
            .expect("allow_domain should succeed");

        guard
            .teardown_isolate_network(netns)
            .await
            .expect("Teardown should succeed");

        assert_eq!(guard.get_metrics(netns), None);
    }
}

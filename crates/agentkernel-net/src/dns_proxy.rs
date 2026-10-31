use crate::dns_proto::{
    build_dns_error_response, build_dns_response, parse_dns_query, DnsRcode, DnsRecordType,
};
use crate::nftables::NftablesGenerator;
use crate::policy::EgressPolicy;
use crate::NetError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

/// Decision outcome for an audited DNS query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsAuditDecision {
    Allowed,
    Blocked,
}

/// Telemetry audit log entry recording DNS interception activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAuditEntry {
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub client_ip: IpAddr,
    pub decision: DnsAuditDecision,
    pub resolved_ips: Vec<IpAddr>,
}

/// Abstract DNS resolver trait for upstream name resolution.
#[async_trait]
pub trait DnsResolver: Send + Sync + std::fmt::Debug {
    async fn resolve(&self, domain: &str, qtype: DnsRecordType) -> Result<Vec<IpAddr>, String>;
}

/// System resolver using tokio::net::lookup_host for host name resolution.
#[derive(Debug, Default)]
pub struct SystemResolver;

#[async_trait]
impl DnsResolver for SystemResolver {
    async fn resolve(&self, domain: &str, qtype: DnsRecordType) -> Result<Vec<IpAddr>, String> {
        let host_port = format!("{}:80", domain);
        let socket_addrs = tokio::net::lookup_host(&host_port)
            .await
            .map_err(|e| format!("System DNS lookup failed for {}: {}", domain, e))?;

        let ips: Vec<IpAddr> = socket_addrs
            .into_iter()
            .map(|sa| sa.ip())
            .filter(|ip| match (qtype, ip) {
                (DnsRecordType::A, IpAddr::V4(_)) => true,
                (DnsRecordType::AAAA, IpAddr::V6(_)) => true,
                _ => false,
            })
            .collect();

        if ips.is_empty() {
            Err(format!("No matching records found for {}", domain))
        } else {
            Ok(ips)
        }
    }
}

/// Mock resolver for fast, deterministic, offline unit testing.
#[derive(Debug, Default, Clone)]
pub struct MockResolver {
    records: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
}

impl MockResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, domain: &str, ips: Vec<IpAddr>) {
        let mut map = self.records.write().unwrap();
        map.insert(domain.trim_end_matches('.').to_ascii_lowercase(), ips);
    }
}

#[async_trait]
impl DnsResolver for MockResolver {
    async fn resolve(&self, domain: &str, qtype: DnsRecordType) -> Result<Vec<IpAddr>, String> {
        let norm = domain.trim_end_matches('.').to_ascii_lowercase();
        let map = self.records.read().unwrap();

        if let Some(ips) = map.get(&norm) {
            let filtered: Vec<IpAddr> = ips
                .iter()
                .cloned()
                .filter(|ip| match (qtype, ip) {
                    (DnsRecordType::A, IpAddr::V4(_)) => true,
                    (DnsRecordType::AAAA, IpAddr::V6(_)) => true,
                    _ => false,
                })
                .collect();

            if filtered.is_empty() {
                Err(format!("No records of type {:?} for {}", qtype, domain))
            } else {
                Ok(filtered)
            }
        } else {
            Err(format!("Domain not found in mock resolver: {}", domain))
        }
    }
}

/// Smart DNS Proxy Server that intercepts queries, verifies egress domain policy,
/// defends against DNS rebinding, records audit telemetry, and updates dynamic nftables rulesets.
#[derive(Debug, Clone)]
pub struct DnsProxy {
    local_addr: SocketAddr,
    policy: Arc<RwLock<EgressPolicy>>,
    resolver: Arc<dyn DnsResolver>,
    nft_generator: Option<NftablesGenerator>,
    shutdown_tx: broadcast::Sender<()>,
    audit_log: Arc<RwLock<VecDeque<DnsAuditEntry>>>,
    max_audit_entries: usize,
    allowed_requests_total: Arc<AtomicU64>,
    blocked_requests_total: Arc<AtomicU64>,
}

impl DnsProxy {
    /// Binds the DNS proxy UDP socket on the specified address with default audit history capacity (100).
    pub async fn bind(
        bind_addr: &str,
        policy: EgressPolicy,
        resolver: Arc<dyn DnsResolver>,
        nft_generator: Option<NftablesGenerator>,
    ) -> Result<(Self, UdpSocket), NetError> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| NetError::Dns(format!("Failed to bind DNS UDP socket on {}: {}", bind_addr, e)))?;

        let local_addr = socket
            .local_addr()
            .map_err(|e| NetError::Dns(format!("Failed to get local address: {}", e)))?;

        let (shutdown_tx, _) = broadcast::channel(1);

        let proxy = Self {
            local_addr,
            policy: Arc::new(RwLock::new(policy)),
            resolver,
            nft_generator,
            shutdown_tx,
            audit_log: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            max_audit_entries: 100,
            allowed_requests_total: Arc::new(AtomicU64::new(0)),
            blocked_requests_total: Arc::new(AtomicU64::new(0)),
        };

        Ok((proxy, socket))
    }

    /// Sets the maximum capacity for retained DNS audit history entries.
    pub fn with_audit_capacity(mut self, capacity: usize) -> Self {
        self.max_audit_entries = capacity.max(1);
        self
    }

    /// Records an audit log entry into the bounded ring-buffer.
    fn record_audit(
        &self,
        domain: String,
        client_ip: IpAddr,
        decision: DnsAuditDecision,
        resolved_ips: Vec<IpAddr>,
    ) {
        let entry = DnsAuditEntry {
            timestamp: Utc::now(),
            domain,
            client_ip,
            decision,
            resolved_ips,
        };
        let mut log = self.audit_log.write().unwrap();
        if log.len() >= self.max_audit_entries {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Spawns the DNS proxy server task in the background.
    pub fn spawn_server(&self, socket: UdpSocket) -> JoinHandle<()> {
        let socket = Arc::new(socket);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let proxy_clone = self.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            loop {
                tokio::select! {
                    recv_res = socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((size, peer_addr)) => {
                                let query_bytes = buf[..size].to_vec();
                                let sock = Arc::clone(&socket);
                                let proxy_state = proxy_clone.clone();

                                tokio::spawn(async move {
                                    proxy_state.handle_packet(&sock, &query_bytes, peer_addr).await;
                                });
                            }
                            Err(e) => {
                                tracing::warn!("DNS UDP receive error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("DNS Proxy shutdown signal received");
                        break;
                    }
                }
            }
        })
    }

    /// Handles a single incoming DNS query packet.
    async fn handle_packet(&self, socket: &UdpSocket, packet_data: &[u8], peer_addr: SocketAddr) {
        let query = match parse_dns_query(packet_data) {
            Ok(q) => q,
            Err(_) => return, // Ignore malformed non-DNS packets
        };

        let policy = self.policy.read().unwrap().clone();

        // 1. Validate domain against Egress allowlist
        if !policy.is_domain_allowed(&query.name) {
            self.blocked_requests_total.fetch_add(1, Ordering::SeqCst);
            self.record_audit(
                query.name.clone(),
                peer_addr.ip(),
                DnsAuditDecision::Blocked,
                Vec::new(),
            );
            let resp = build_dns_error_response(&query, DnsRcode::Refused);
            let _ = socket.send_to(&resp, peer_addr).await;
            return;
        }

        // 2. Resolve domain
        let resolved_ips = match self.resolver.resolve(&query.name, query.qtype).await {
            Ok(ips) => ips,
            Err(_) => {
                self.blocked_requests_total.fetch_add(1, Ordering::SeqCst);
                self.record_audit(
                    query.name.clone(),
                    peer_addr.ip(),
                    DnsAuditDecision::Blocked,
                    Vec::new(),
                );
                let resp = build_dns_error_response(&query, DnsRcode::NameError);
                let _ = socket.send_to(&resp, peer_addr).await;
                return;
            }
        };

        // 3. DNS Rebinding Defense: verify resolved IPs against blocked CIDRs
        let has_blocked_ip = resolved_ips.iter().any(|&ip| policy.is_ip_blocked(ip));
        if has_blocked_ip {
            // Drop/Refuse attempt to access cloud metadata or RFC1918 private network via DNS rebinding
            self.blocked_requests_total.fetch_add(1, Ordering::SeqCst);
            self.record_audit(
                query.name.clone(),
                peer_addr.ip(),
                DnsAuditDecision::Blocked,
                resolved_ips,
            );
            let resp = build_dns_error_response(&query, DnsRcode::Refused);
            let _ = socket.send_to(&resp, peer_addr).await;
            return;
        }

        // 4. Update dynamic nftables firewall allowlist
        if let Some(ref nft) = self.nft_generator {
            for &ip in &resolved_ips {
                nft.add_ip(ip);
            }
        }

        self.allowed_requests_total.fetch_add(1, Ordering::SeqCst);
        self.record_audit(
            query.name.clone(),
            peer_addr.ip(),
            DnsAuditDecision::Allowed,
            resolved_ips.clone(),
        );

        // 5. Build and send successful DNS answer
        let resp = build_dns_response(&query, &resolved_ips, 300);
        let _ = socket.send_to(&resp, peer_addr).await;
    }

    /// Dynamically adds a domain to the proxy's active allowlist during runtime.
    pub fn allow_domain(&self, domain: &str) {
        let mut policy = self.policy.write().unwrap();
        policy.allow_domain(domain);
    }

    /// Returns a chronological snapshot list of recent DNS audit entries.
    pub fn get_audit_log(&self) -> Vec<DnsAuditEntry> {
        let log = self.audit_log.read().unwrap();
        log.iter().cloned().collect()
    }

    /// Returns the total counter of allowed and successfully resolved requests.
    pub fn allowed_requests_total(&self) -> u64 {
        self.allowed_requests_total.load(Ordering::SeqCst)
    }

    /// Returns the total counter of blocked or rejected requests.
    pub fn blocked_requests_total(&self) -> u64 {
        self.blocked_requests_total.load(Ordering::SeqCst)
    }

    /// Returns the bound local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the bound local UDP port.
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// Signals the DNS server task to stop.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Returns access to the internal dynamic nftables generator.
    pub fn nftables_generator(&self) -> Option<&NftablesGenerator> {
        self.nft_generator.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_proto::{build_dns_query_packet, DnsRecordType};
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_dns_proxy_allowed_domain() {
        let mock_resolver = Arc::new(MockResolver::new());
        mock_resolver.insert(
            "github.com",
            vec![IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4))],
        );

        let policy = EgressPolicy::default();
        let nft = NftablesGenerator::new("agentkernel_dns", policy.clone());

        let (proxy, socket) = DnsProxy::bind("127.0.0.1:0", policy, mock_resolver, Some(nft.clone()))
            .await
            .expect("Bind failed");

        let proxy_addr = proxy.local_addr();
        let server_handle = proxy.spawn_server(socket);

        // Client socket to send DNS query
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query_pkt = build_dns_query_packet(0x1234, "github.com", DnsRecordType::A);

        client.send_to(&query_pkt, proxy_addr).await.unwrap();

        let mut resp_buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut resp_buf),
        )
        .await
        .expect("Timeout waiting for DNS response")
        .expect("Recv failed");

        let resp = &resp_buf[..len];
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x1234);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x0f, 0); // NoError
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // 1 answer

        // Verify dynamic allowlist was updated
        assert!(nft.contains_ip(&IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4))));

        proxy.shutdown();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_dns_proxy_blocked_domain() {
        let mock_resolver = Arc::new(MockResolver::new());
        mock_resolver.insert(
            "evil.com",
            vec![IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6))],
        );

        let policy = EgressPolicy::default();
        let (proxy, socket) = DnsProxy::bind("127.0.0.1:0", policy, mock_resolver, None)
            .await
            .expect("Bind failed");

        let proxy_addr = proxy.local_addr();
        let server_handle = proxy.spawn_server(socket);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query_pkt = build_dns_query_packet(0x5678, "evil.com", DnsRecordType::A);

        client.send_to(&query_pkt, proxy_addr).await.unwrap();

        let mut resp_buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut resp_buf),
        )
        .await
        .expect("Timeout waiting for DNS response")
        .expect("Recv failed");

        let resp = &resp_buf[..len];
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x5678);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x0f, 5); // RCODE = 5 (Refused)

        proxy.shutdown();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_dns_proxy_rebinding_defense() {
        let mock_resolver = Arc::new(MockResolver::new());
        // Domain is in allowed list (subdomain of github.com), but resolves to AWS/Cloud Metadata IP!
        mock_resolver.insert(
            "metadata.github.com",
            vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        );

        let policy = EgressPolicy::default();
        let nft = NftablesGenerator::new("agentkernel_rebinding", policy.clone());

        let (proxy, socket) = DnsProxy::bind("127.0.0.1:0", policy, mock_resolver, Some(nft.clone()))
            .await
            .expect("Bind failed");

        let proxy_addr = proxy.local_addr();
        let server_handle = proxy.spawn_server(socket);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query_pkt = build_dns_query_packet(0x7777, "metadata.github.com", DnsRecordType::A);

        client.send_to(&query_pkt, proxy_addr).await.unwrap();

        let mut resp_buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut resp_buf),
        )
        .await
        .expect("Timeout waiting for DNS response")
        .expect("Recv failed");

        let resp = &resp_buf[..len];
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_eq!(flags & 0x0f, 5); // REFUSED due to metadata IP block!

        // Ensure metadata IP was NOT added to allowlist
        assert!(!nft.contains_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));

        proxy.shutdown();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_dns_proxy_audit_log_and_metrics() {
        let mock_resolver = Arc::new(MockResolver::new());
        mock_resolver.insert(
            "crates.io",
            vec![IpAddr::V4(Ipv4Addr::new(146, 75, 30, 217))],
        );

        let policy = EgressPolicy::default();
        let (proxy, socket) = DnsProxy::bind("127.0.0.1:0", policy, mock_resolver, None)
            .await
            .expect("Bind failed");

        let proxy_addr = proxy.local_addr();
        let server_handle = proxy.spawn_server(socket);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 1. Allowed request
        let allowed_query = build_dns_query_packet(0x1111, "crates.io", DnsRecordType::A);
        client.send_to(&allowed_query, proxy_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let _ = client.recv_from(&mut buf).await.unwrap();

        // 2. Blocked request
        let blocked_query = build_dns_query_packet(0x2222, "malicious.site", DnsRecordType::A);
        client.send_to(&blocked_query, proxy_addr).await.unwrap();
        let _ = client.recv_from(&mut buf).await.unwrap();

        // Small delay to ensure audit logs processed
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(proxy.allowed_requests_total(), 1);
        assert_eq!(proxy.blocked_requests_total(), 1);

        let audit = proxy.get_audit_log();
        assert_eq!(audit.len(), 2);

        assert_eq!(audit[0].domain, "crates.io");
        assert_eq!(audit[0].decision, DnsAuditDecision::Allowed);
        assert_eq!(
            audit[0].resolved_ips,
            vec![IpAddr::V4(Ipv4Addr::new(146, 75, 30, 217))]
        );

        assert_eq!(audit[1].domain, "malicious.site");
        assert_eq!(audit[1].decision, DnsAuditDecision::Blocked);
        assert!(audit[1].resolved_ips.is_empty());

        proxy.shutdown();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_dns_proxy_dynamic_allow_domain() {
        let mock_resolver = Arc::new(MockResolver::new());
        mock_resolver.insert(
            "api.internal.company",
            vec![IpAddr::V4(Ipv4Addr::new(140, 82, 112, 10))],
        );

        let policy = EgressPolicy::default();
        let (proxy, socket) = DnsProxy::bind("127.0.0.1:0", policy, mock_resolver, None)
            .await
            .expect("Bind failed");

        let proxy_addr = proxy.local_addr();
        let server_handle = proxy.spawn_server(socket);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query_pkt = build_dns_query_packet(0x3333, "api.internal.company", DnsRecordType::A);

        // Before allow_domain: query should be refused
        client.send_to(&query_pkt, proxy_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (_len, _) = client.recv_from(&mut buf).await.unwrap();
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(flags & 0x0f, 5); // Refused
        assert_eq!(proxy.blocked_requests_total(), 1);

        // Dynamically allow domain
        proxy.allow_domain("api.internal.company");

        // After allow_domain: query should be allowed
        client.send_to(&query_pkt, proxy_addr).await.unwrap();
        let (len2, _) = client.recv_from(&mut buf).await.unwrap();
        assert!(len2 > 0);
        let flags2 = u16::from_be_bytes([buf[2], buf[3]]);
        assert_eq!(flags2 & 0x0f, 0); // NoError
        assert_eq!(proxy.allowed_requests_total(), 1);

        proxy.shutdown();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn test_dns_proxy_audit_capacity_eviction() {
        let mock_resolver = Arc::new(MockResolver::new());
        for i in 1..=5 {
            mock_resolver.insert(
                &format!("host{}.github.com", i),
                vec![IpAddr::V4(Ipv4Addr::new(140, 82, 121, i as u8))],
            );
        }

        let policy = EgressPolicy::default();
        let (proxy, socket) = DnsProxy::bind("127.0.0.1:0", policy, mock_resolver, None)
            .await
            .expect("Bind failed");

        // Set audit capacity to 3
        let proxy = proxy.with_audit_capacity(3);
        let proxy_addr = proxy.local_addr();
        let server_handle = proxy.spawn_server(socket);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for i in 1..=5 {
            let pkt = build_dns_query_packet(
                0x4000 + i as u16,
                &format!("host{}.github.com", i),
                DnsRecordType::A,
            );
            client.send_to(&pkt, proxy_addr).await.unwrap();
            let mut buf = [0u8; 512];
            let _ = client.recv_from(&mut buf).await.unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let audit = proxy.get_audit_log();
        assert_eq!(audit.len(), 3, "Audit ring buffer should be capped at 3");
        assert_eq!(audit[0].domain, "host3.github.com");
        assert_eq!(audit[1].domain, "host4.github.com");
        assert_eq!(audit[2].domain, "host5.github.com");

        proxy.shutdown();
        let _ = server_handle.await;
    }
}

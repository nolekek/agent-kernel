//! AgentKernel Net: Smart DNS Proxy & Egress Guard.

pub mod controller;
pub mod dns_proto;
pub mod dns_proxy;
pub mod nftables;
pub mod policy;

pub use controller::SmartNetGuard;
pub use dns_proto::{DnsQuery, DnsRcode, DnsRecordType};
pub use dns_proxy::{DnsProxy, DnsResolver, MockResolver, SystemResolver};
pub use nftables::NftablesGenerator;
pub use policy::{CidrBlock, EgressPolicy};

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetError {
    #[error("Network namespace setup failed: {0}")]
    Netns(String),
    #[error("Firewall rule failure: {0}")]
    Firewall(String),
    #[error("DNS server error: {0}")]
    Dns(String),
}

#[async_trait]
pub trait NetworkController: Send + Sync {
    async fn setup_isolate_network(&self, netns_name: &str, policy: &EgressPolicy) -> Result<(), NetError>;
    async fn teardown_isolate_network(&self, netns_name: &str) -> Result<(), NetError>;
}

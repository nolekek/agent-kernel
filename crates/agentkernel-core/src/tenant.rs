//! Multi-Tenancy & Quota Management for AgentKernel.
//! Manages tenant registrations, API key authentication, and atomic concurrency quotas.

use crate::metrics::MetricsRegistry;
use crate::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Strongly-typed identifier for a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn new<S: Into<String>>(id: S) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for TenantId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for TenantId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for TenantId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Tenant configuration defining credentials and quota limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    pub tenant_id: TenantId,
    pub name: String,
    pub api_key: String,
    pub max_concurrent_sandboxes: usize,
    pub max_memory_bytes: u64,
    pub max_cpu_quota_us: u64,
}

impl TenantConfig {
    pub fn new(
        tenant_id: impl Into<TenantId>,
        name: impl Into<String>,
        api_key: impl Into<String>,
        max_concurrent_sandboxes: usize,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            name: name.into(),
            api_key: api_key.into(),
            max_concurrent_sandboxes,
            max_memory_bytes: 1024 * 1024 * 1024, // 1 GB default
            max_cpu_quota_us: 100_000,            // 100 ms default
        }
    }

    pub fn with_memory_limit(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    pub fn with_cpu_quota(mut self, cpu_us: u64) -> Self {
        self.max_cpu_quota_us = cpu_us;
        self
    }
}

/// Thread-safe Multi-Tenancy and Quota Manager.
pub struct TenantManager {
    tenants: RwLock<HashMap<TenantId, TenantConfig>>,
    api_keys: RwLock<HashMap<String, TenantId>>,
    active_sandboxes: RwLock<HashMap<TenantId, HashSet<String>>>,
    session_to_tenant: RwLock<HashMap<String, TenantId>>,
    metrics: Option<Arc<MetricsRegistry>>,
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantManager {
    pub fn new() -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
            api_keys: RwLock::new(HashMap::new()),
            active_sandboxes: RwLock::new(HashMap::new()),
            session_to_tenant: RwLock::new(HashMap::new()),
            metrics: None,
        }
    }

    pub fn with_metrics(metrics: Arc<MetricsRegistry>) -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
            api_keys: RwLock::new(HashMap::new()),
            active_sandboxes: RwLock::new(HashMap::new()),
            session_to_tenant: RwLock::new(HashMap::new()),
            metrics: Some(metrics),
        }
    }

    pub fn attach_metrics(&mut self, metrics: Arc<MetricsRegistry>) {
        self.metrics = Some(metrics);
    }

    /// Registers a tenant configuration and maps their API key.
    pub async fn register_tenant(&self, config: TenantConfig) -> Result<(), CoreError> {
        let mut tenants = self.tenants.write().await;
        let mut api_keys = self.api_keys.write().await;

        api_keys.insert(config.api_key.clone(), config.tenant_id.clone());
        tenants.insert(config.tenant_id.clone(), config);
        Ok(())
    }

    /// Validates an API key and returns the corresponding tenant config.
    pub async fn authenticate_key(&self, api_key: &str) -> Result<TenantConfig, CoreError> {
        let api_keys = self.api_keys.read().await;
        let tenant_id = api_keys
            .get(api_key)
            .ok_or_else(|| CoreError::Unauthorized("Invalid API key".to_string()))?;

        let tenants = self.tenants.read().await;
        tenants
            .get(tenant_id)
            .cloned()
            .ok_or_else(|| CoreError::NotFound(format!("Tenant '{tenant_id}' not found")))
    }

    /// Atomically acquires a sandbox lease for the specified tenant, enforcing concurrency quota.
    pub async fn acquire_sandbox_lease(
        &self,
        tenant_id: &TenantId,
        session_id: &str,
    ) -> Result<(), CoreError> {
        let tenants = self.tenants.read().await;
        let config = tenants
            .get(tenant_id)
            .ok_or_else(|| CoreError::NotFound(format!("Tenant '{tenant_id}' not found")))?;

        let mut active = self.active_sandboxes.write().await;
        let mut session_map = self.session_to_tenant.write().await;

        let tenant_sessions = active.entry(tenant_id.clone()).or_default();
        if tenant_sessions.len() >= config.max_concurrent_sandboxes {
            if let Some(metrics) = &self.metrics {
                metrics.quota_violations_total.inc();
            }
            return Err(CoreError::QuotaExceeded(format!(
                "Tenant '{}' exceeded concurrent sandboxes quota (limit: {}, current: {})",
                tenant_id,
                config.max_concurrent_sandboxes,
                tenant_sessions.len()
            )));
        }

        tenant_sessions.insert(session_id.to_string());
        session_map.insert(session_id.to_string(), tenant_id.clone());
        Ok(())
    }

    /// Releases a leased sandbox for the specified tenant.
    pub async fn release_sandbox_lease(&self, tenant_id: &TenantId, session_id: &str) {
        let mut active = self.active_sandboxes.write().await;
        let mut session_map = self.session_to_tenant.write().await;

        if let Some(set) = active.get_mut(tenant_id) {
            set.remove(session_id);
        }
        session_map.remove(session_id);
    }

    /// Releases a session by ID and returns the tenant that owned it.
    pub async fn release_session(&self, session_id: &str) -> Option<TenantId> {
        let mut session_map = self.session_to_tenant.write().await;
        if let Some(tenant_id) = session_map.remove(session_id) {
            let mut active = self.active_sandboxes.write().await;
            if let Some(set) = active.get_mut(&tenant_id) {
                set.remove(session_id);
            }
            Some(tenant_id)
        } else {
            None
        }
    }

    /// Validates whether the given tenant owns the specified session.
    pub async fn validate_session_access(
        &self,
        tenant_id: &TenantId,
        session_id: &str,
    ) -> Result<(), CoreError> {
        let session_map = self.session_to_tenant.read().await;
        match session_map.get(session_id) {
            Some(owner) if owner == tenant_id => Ok(()),
            Some(_) => Err(CoreError::Unauthorized(format!(
                "Session '{session_id}' does not belong to tenant '{tenant_id}'"
            ))),
            None => Err(CoreError::NotFound(format!("Session '{session_id}' not found"))),
        }
    }

    /// Gets the owner TenantId of a session, if any.
    pub async fn get_session_owner(&self, session_id: &str) -> Option<TenantId> {
        let session_map = self.session_to_tenant.read().await;
        session_map.get(session_id).cloned()
    }

    /// Returns the number of active leased sandboxes for a specific tenant.
    pub async fn active_sandbox_count(&self, tenant_id: &TenantId) -> usize {
        let active = self.active_sandboxes.read().await;
        active.get(tenant_id).map(|s| s.len()).unwrap_or(0)
    }

    /// Returns the total number of active leased sandboxes across all tenants.
    pub async fn total_active_sandboxes(&self) -> usize {
        let session_map = self.session_to_tenant.read().await;
        session_map.len()
    }

    /// Returns whether any tenants are registered.
    pub async fn has_tenants(&self) -> bool {
        let tenants = self.tenants.read().await;
        !tenants.is_empty()
    }

    /// Retrieves a tenant config by TenantId.
    pub async fn get_tenant(&self, tenant_id: &TenantId) -> Option<TenantConfig> {
        let tenants = self.tenants.read().await;
        tenants.get(tenant_id).cloned()
    }

    /// Lists all registered tenant configurations.
    pub async fn list_tenants(&self) -> Vec<TenantConfig> {
        let tenants = self.tenants.read().await;
        tenants.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tenant_registration_and_auth() {
        let mgr = TenantManager::new();
        let cfg = TenantConfig::new("tenant-alpha", "Alpha Corp", "ak-sec-12345", 2);

        mgr.register_tenant(cfg).await.expect("registration");
        assert!(mgr.has_tenants().await);

        // Valid auth
        let authed = mgr.authenticate_key("ak-sec-12345").await.expect("valid auth");
        assert_eq!(authed.tenant_id, TenantId::new("tenant-alpha"));
        assert_eq!(authed.name, "Alpha Corp");

        // Invalid auth
        let err = mgr.authenticate_key("wrong-key").await;
        assert!(matches!(err, Err(CoreError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn test_tenant_quota_accounting_and_exceeded() {
        let metrics = Arc::new(MetricsRegistry::new());
        let mgr = TenantManager::with_metrics(metrics.clone());

        let cfg = TenantConfig::new("tenant-beta", "Beta Ltd", "ak-sec-beta", 2);
        mgr.register_tenant(cfg).await.unwrap();

        let tid = TenantId::new("tenant-beta");

        // 1. Lease sandbox 1 - should succeed
        mgr.acquire_sandbox_lease(&tid, "sb-1").await.expect("lease 1");
        assert_eq!(mgr.active_sandbox_count(&tid).await, 1);
        assert_eq!(mgr.total_active_sandboxes().await, 1);

        // 2. Lease sandbox 2 - should succeed
        mgr.acquire_sandbox_lease(&tid, "sb-2").await.expect("lease 2");
        assert_eq!(mgr.active_sandbox_count(&tid).await, 2);

        // 3. Lease sandbox 3 - should fail with QuotaExceeded
        let res3 = mgr.acquire_sandbox_lease(&tid, "sb-3").await;
        assert!(
            matches!(res3, Err(CoreError::QuotaExceeded(_))),
            "Expected QuotaExceeded error, got: {:?}",
            res3
        );
        assert_eq!(metrics.quota_violations_total.get(), 1);
        assert_eq!(mgr.active_sandbox_count(&tid).await, 2);

        // 4. Release sb-1
        mgr.release_sandbox_lease(&tid, "sb-1").await;
        assert_eq!(mgr.active_sandbox_count(&tid).await, 1);

        // 5. Now lease sb-3 succeeds
        mgr.acquire_sandbox_lease(&tid, "sb-3").await.expect("lease 3 after release");
        assert_eq!(mgr.active_sandbox_count(&tid).await, 2);

        // 6. Release via release_session
        let owner = mgr.release_session("sb-2").await;
        assert_eq!(owner, Some(tid.clone()));
        assert_eq!(mgr.active_sandbox_count(&tid).await, 1);
    }

    #[tokio::test]
    async fn test_tenant_isolation_session_access() {
        let mgr = TenantManager::new();
        let cfg_a = TenantConfig::new("tenant-a", "Tenant A", "key-a", 5);
        let cfg_b = TenantConfig::new("tenant-b", "Tenant B", "key-b", 5);

        mgr.register_tenant(cfg_a).await.unwrap();
        mgr.register_tenant(cfg_b).await.unwrap();

        let tid_a = TenantId::new("tenant-a");
        let tid_b = TenantId::new("tenant-b");

        mgr.acquire_sandbox_lease(&tid_a, "session-a-1").await.unwrap();
        mgr.acquire_sandbox_lease(&tid_b, "session-b-1").await.unwrap();

        // Tenant A accessing session-a-1: ok
        assert!(mgr.validate_session_access(&tid_a, "session-a-1").await.is_ok());

        // Tenant A accessing session-b-1: Unauthorized
        let cross_access = mgr.validate_session_access(&tid_a, "session-b-1").await;
        assert!(matches!(cross_access, Err(CoreError::Unauthorized(_))));

        // Tenant B accessing non-existent session: NotFound
        let not_found = mgr.validate_session_access(&tid_b, "session-nonexistent").await;
        assert!(matches!(not_found, Err(CoreError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_tenant_config_builders_and_getters() {
        let tid = TenantId::new("cust-99");
        assert_eq!(tid.as_str(), "cust-99");
        assert_eq!(format!("{tid}"), "cust-99");
        assert_eq!(tid.as_ref(), "cust-99");
        assert_eq!(&*tid, "cust-99");

        let cfg = TenantConfig::new(tid.clone(), "Customer 99", "secret-99", 10)
            .with_memory_limit(2 * 1024 * 1024 * 1024)
            .with_cpu_quota(50_000);

        assert_eq!(cfg.tenant_id, tid);
        assert_eq!(cfg.name, "Customer 99");
        assert_eq!(cfg.api_key, "secret-99");
        assert_eq!(cfg.max_concurrent_sandboxes, 10);
        assert_eq!(cfg.max_memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(cfg.max_cpu_quota_us, 50_000);

        let mgr = TenantManager::new();
        mgr.register_tenant(cfg).await.unwrap();

        let retrieved = mgr.get_tenant(&tid).await.expect("retrieved");
        assert_eq!(retrieved.name, "Customer 99");

        let list = mgr.list_tenants().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].tenant_id, tid);
    }
}

use crate::sandbox::{DefaultSandboxSession, LeasedSandboxSession, SandboxConfig, SandboxSession};
use crate::CoreError;
use agentkernel_fs::StorageEngine;
use agentkernel_runtime::RuntimeDriver;
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub target_warm_count: usize,
    pub max_active: usize,
    pub idle_ttl: Duration,
    pub default_base_root: PathBuf,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            target_warm_count: 3,
            max_active: 10,
            idle_ttl: Duration::from_secs(300),
            default_base_root: std::env::temp_dir().join("agentkernel_base_root"),
        }
    }
}

impl PoolConfig {
    pub fn new(target_warm: usize, max_active: usize) -> Self {
        Self {
            target_warm_count: target_warm,
            max_active,
            ..Default::default()
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.idle_ttl = ttl;
        self
    }
}

#[async_trait]
pub trait PoolManager: Send + Sync {
    async fn acquire_sandbox(&self, config: SandboxConfig) -> Result<Arc<dyn SandboxSession>, CoreError>;
    async fn release_sandbox(&self, session_id: &str) -> Result<(), CoreError>;
    async fn warm_count(&self) -> usize;
    async fn leased_count(&self) -> usize {
        0
    }
    async fn get_session(&self, session_id: &str) -> Result<Arc<dyn SandboxSession>, CoreError> {
        let _ = session_id;
        Err(CoreError::NotFound(session_id.to_string()))
    }
}

/// Thread-safe Pre-warmed Sandbox Pool with background replenishment and TTL eviction.
pub struct WarmPool {
    config: PoolConfig,
    storage_engine: Arc<dyn StorageEngine>,
    runtime_driver: Arc<dyn RuntimeDriver>,
    warm_queue: Arc<Mutex<VecDeque<Arc<DefaultSandboxSession>>>>,
    leased_sandboxes: Arc<RwLock<HashMap<String, Arc<LeasedSandboxSession>>>>,
    is_closed: Arc<AtomicBool>,
}

impl WarmPool {
    /// Creates and initializes the WarmPool, immediately pre-warming to target_warm_count.
    pub async fn new(
        config: PoolConfig,
        storage_engine: Arc<dyn StorageEngine>,
        runtime_driver: Arc<dyn RuntimeDriver>,
    ) -> Arc<Self> {
        let pool = Arc::new(Self {
            config,
            storage_engine,
            runtime_driver,
            warm_queue: Arc::new(Mutex::new(VecDeque::new())),
            leased_sandboxes: Arc::new(RwLock::new(HashMap::new())),
            is_closed: Arc::new(AtomicBool::new(false)),
        });

        // Initial pre-warm up to target_warm_count
        pool.replenish_sync().await;

        // Spawn background TTL janitor task
        let pool_weak = Arc::downgrade(&pool);
        tokio::spawn(async move {
            while let Some(pool_arc) = pool_weak.upgrade() {
                if pool_arc.is_closed.load(Ordering::Relaxed) {
                    break;
                }
                let swept = pool_arc.sweep_expired().await;
                if swept > 0 {
                    debug!(swept = swept, "Swept expired inactive sandboxes");
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });

        pool
    }

    /// Synchronously replenishes the pool up to the configured target_warm_count.
    pub async fn replenish_sync(&self) {
        let mut queue = self.warm_queue.lock().await;
        while queue.len() < self.config.target_warm_count {
            if self.is_closed.load(Ordering::Relaxed) {
                break;
            }

            let cfg = SandboxConfig::default();
            match DefaultSandboxSession::create_warm(
                cfg,
                self.storage_engine.clone(),
                self.runtime_driver.clone(),
            )
            .await
            {
                Ok(session) => {
                    queue.push_back(Arc::new(session));
                }
                Err(e) => {
                    error!("Failed to create pre-warmed sandbox: {}", e);
                    break;
                }
            }
        }
        info!(
            current_warm = queue.len(),
            target = self.config.target_warm_count,
            "Pool replenishment check complete"
        );
    }

    /// Spawns an asynchronous background task to replenish warm sandboxes after a lease.
    pub fn trigger_background_replenish(self: &Arc<Self>) {
        let pool_clone = self.clone();
        tokio::spawn(async move {
            pool_clone.replenish_sync().await;
        });
    }

    /// Scans leased sandboxes and terminates any that have exceeded the idle TTL.
    pub async fn sweep_expired(&self) -> usize {
        let mut expired_ids = Vec::new();
        let now = std::time::Instant::now();

        {
            let leased = self.leased_sandboxes.read().await;
            for (id, session) in leased.iter() {
                let last = session.last_active().await;
                if now.duration_since(last) > self.config.idle_ttl {
                    expired_ids.push(id.clone());
                }
            }
        }

        let mut count = 0;
        for id in expired_ids {
            info!(session_id = %id, "Reaping idle sandbox exceeding TTL");
            let _ = self.release_sandbox(&id).await;
            count += 1;
        }

        count
    }

    pub async fn leased_count(&self) -> usize {
        self.leased_sandboxes.read().await.len()
    }

    /// Closes the pool and terminates all sandboxes.
    pub async fn shutdown(&self) {
        self.is_closed.store(true, Ordering::SeqCst);

        // Clear and terminate warm queue
        let mut queue = self.warm_queue.lock().await;
        while let Some(session) = queue.pop_front() {
            let _ = session.terminate().await;
        }

        // Clear and terminate leased sandboxes
        let mut leased = self.leased_sandboxes.write().await;
        for (_, session) in leased.drain() {
            let _ = session.terminate().await;
        }

        info!("WarmPool shut down successfully");
    }
}

#[async_trait]
impl PoolManager for WarmPool {
    async fn acquire_sandbox(&self, config: SandboxConfig) -> Result<Arc<dyn SandboxSession>, CoreError> {
        if self.is_closed.load(Ordering::Relaxed) {
            return Err(CoreError::InvalidState("Pool is closed".to_string()));
        }

        // Capacity check: Cannot exceed max_active
        let current_active = self.leased_sandboxes.read().await.len();
        if current_active >= self.config.max_active {
            return Err(CoreError::PoolExhausted);
        }

        // Try to pop a pre-warmed sandbox
        let warm_session = {
            let mut queue = self.warm_queue.lock().await;
            queue.pop_front()
        };

        let inner_session = match warm_session {
            Some(s) => {
                s.lease(config.clone()).await?;
                s
            }
            None => {
                // Create a fresh session on demand
                let s = DefaultSandboxSession::create_warm(
                    config.clone(),
                    self.storage_engine.clone(),
                    self.runtime_driver.clone(),
                )
                .await?;
                s.lease(config.clone()).await?;
                Arc::new(s)
            }
        };

        let session_id = config.session_id.clone();
        let leased_session = Arc::new(LeasedSandboxSession::new(session_id.clone(), inner_session));

        self.leased_sandboxes
            .write()
            .await
            .insert(session_id.clone(), leased_session.clone());

        // Background replenishment to keep pool at target_warm_count
        let pool_self = self.warm_queue.clone();
        let target = self.config.target_warm_count;
        let storage = self.storage_engine.clone();
        let runtime = self.runtime_driver.clone();
        let closed = self.is_closed.clone();

        tokio::spawn(async move {
            let mut queue = pool_self.lock().await;
            while queue.len() < target {
                if closed.load(Ordering::Relaxed) {
                    break;
                }
                let cfg = SandboxConfig::default();
                if let Ok(s) = DefaultSandboxSession::create_warm(cfg, storage.clone(), runtime.clone()).await {
                    queue.push_back(Arc::new(s));
                } else {
                    break;
                }
            }
        });

        info!(session_id = %session_id, "Sandbox successfully leased from pool");
        Ok(leased_session)
    }

    async fn release_sandbox(&self, session_id: &str) -> Result<(), CoreError> {
        let session = {
            let mut leased = self.leased_sandboxes.write().await;
            leased.remove(session_id)
        };

        match session {
            Some(s) => {
                s.terminate().await?;
                info!(session_id = %session_id, "Sandbox released and terminated");
                Ok(())
            }
            None => Err(CoreError::NotFound(session_id.to_string())),
        }
    }

    async fn warm_count(&self) -> usize {
        self.warm_queue.lock().await.len()
    }

    async fn leased_count(&self) -> usize {
        self.leased_sandboxes.read().await.len()
    }

    async fn get_session(&self, session_id: &str) -> Result<Arc<dyn SandboxSession>, CoreError> {
        let leased = self.leased_sandboxes.read().await;
        match leased.get(session_id) {
            Some(s) => Ok(s.clone() as Arc<dyn SandboxSession>),
            None => Err(CoreError::NotFound(session_id.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkernel_fs::OverlayFsEngine;
    use agentkernel_runtime::PortableRuntimeDriver;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_warm_pool_initial_count_and_lease() {
        let tmp = tempdir().unwrap();
        let storage = Arc::new(OverlayFsEngine::with_storage_dir(tmp.path().join("storage")));
        let runtime = Arc::new(PortableRuntimeDriver::new());

        let pool_cfg = PoolConfig::new(3, 5);
        let pool = WarmPool::new(pool_cfg, storage, runtime).await;

        // Verify initial warm count is 3
        assert_eq!(pool.warm_count().await, 3);
        assert_eq!(pool.leased_count().await, 0);

        // Acquire 1 sandbox
        let cfg1 = SandboxConfig::new("agent_task_1");
        let session1 = pool.acquire_sandbox(cfg1).await.expect("acquire 1");
        assert_eq!(session1.id(), "agent_task_1");

        assert_eq!(pool.leased_count().await, 1);

        // Get session by ID
        let retrieved = pool.get_session("agent_task_1").await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap().id(), "agent_task_1");

        // Wait for background replenishment with polling
        let mut replenished = false;
        for _ in 0..20 {
            if pool.warm_count().await == 3 {
                replenished = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(replenished, "Background replenishment should restore warm count to 3");

        // Release sandbox
        pool.release_sandbox("agent_task_1").await.expect("release 1");
        assert_eq!(pool.leased_count().await, 0);
        assert!(pool.get_session("agent_task_1").await.is_err());

        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_warm_pool_exhaustion_limit() {
        let tmp = tempdir().unwrap();
        let storage = Arc::new(OverlayFsEngine::with_storage_dir(tmp.path().join("storage")));
        let runtime = Arc::new(PortableRuntimeDriver::new());

        // Pool with max_active = 2
        let pool_cfg = PoolConfig::new(1, 2);
        let pool = WarmPool::new(pool_cfg, storage, runtime).await;

        let s1 = pool.acquire_sandbox(SandboxConfig::new("task_1")).await;
        assert!(s1.is_ok());

        let s2 = pool.acquire_sandbox(SandboxConfig::new("task_2")).await;
        assert!(s2.is_ok());

        // 3rd should fail with PoolExhausted
        let s3 = pool.acquire_sandbox(SandboxConfig::new("task_3")).await;
        assert!(matches!(s3, Err(CoreError::PoolExhausted)));

        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_warm_pool_ttl_eviction() {
        let tmp = tempdir().unwrap();
        let storage = Arc::new(OverlayFsEngine::with_storage_dir(tmp.path().join("storage")));
        let runtime = Arc::new(PortableRuntimeDriver::new());

        // Pool with 50ms TTL
        let pool_cfg = PoolConfig::new(1, 5).with_ttl(Duration::from_millis(50));
        let pool = WarmPool::new(pool_cfg, storage, runtime).await;

        let _s1 = pool.acquire_sandbox(SandboxConfig::new("task_short_ttl")).await.unwrap();
        assert_eq!(pool.leased_count().await, 1);

        // Sleep to exceed TTL
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Trigger sweep
        let swept = pool.sweep_expired().await;
        assert_eq!(swept, 1);
        assert_eq!(pool.leased_count().await, 0);

        pool.shutdown().await;
    }
}


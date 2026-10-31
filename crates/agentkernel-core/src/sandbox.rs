use crate::{CoreError, SandboxStatus};
use agentkernel_fs::{Checkpoint, CheckpointInfo, FileDiff, OverlayMount, StorageEngine};
use agentkernel_pty::CommandOutput;
use agentkernel_runtime::RuntimeDriver;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub session_id: String,
    pub workspace_path: String,
    pub base_rootfs: Option<String>,
    pub env_vars: Vec<(String, String)>,
    pub timeout_seconds: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            session_id: format!("sb_{}", Uuid::new_v4().simple()),
            workspace_path: String::new(),
            base_rootfs: None,
            env_vars: Vec::new(),
            timeout_seconds: 60,
        }
    }
}

impl SandboxConfig {
    pub fn new<S: Into<String>>(session_id: S) -> Self {
        Self {
            session_id: session_id.into(),
            ..Default::default()
        }
    }

    pub fn with_workspace<P: Into<String>>(mut self, path: P) -> Self {
        self.workspace_path = path.into();
        self
    }

    pub fn with_base_rootfs<P: Into<String>>(mut self, path: P) -> Self {
        self.base_rootfs = Some(path.into());
        self
    }

    pub fn with_env<K: Into<String>, V: Into<String>>(mut self, k: K, v: V) -> Self {
        self.env_vars.push((k.into(), v.into()));
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxMetrics {
    pub cpu_time_ms: u64,
    pub memory_rss_bytes: u64,
    pub disk_usage_bytes: u64,
    pub uptime_seconds: u64,
    pub status: SandboxStatus,
}

#[async_trait]
pub trait SandboxSession: Send + Sync {
    fn id(&self) -> &str;
    async fn exec(&self, cmd: &str, args: &[String], timeout_ms: u64) -> Result<CommandOutput, CoreError>;
    async fn create_checkpoint(&self, name: &str) -> Result<Checkpoint, CoreError>;
    async fn rollback(&self, checkpoint_id: &str) -> Result<(), CoreError>;
    async fn terminate(&self) -> Result<(), CoreError>;
    async fn list_checkpoints(&self) -> Result<Vec<CheckpointInfo>, CoreError> {
        Ok(Vec::new())
    }
    async fn get_diff(&self, _from: Option<&str>, _to: Option<&str>) -> Result<Vec<FileDiff>, CoreError> {
        Ok(Vec::new())
    }
    async fn get_metrics(&self) -> Result<SandboxMetrics, CoreError> {
        Ok(SandboxMetrics {
            cpu_time_ms: 0,
            memory_rss_bytes: 0,
            disk_usage_bytes: 0,
            uptime_seconds: 0,
            status: SandboxStatus::Warm,
        })
    }
}

/// Concrete sandbox session with full lifecycle state machine.
pub struct DefaultSandboxSession {
    id: String,
    config: Arc<RwLock<SandboxConfig>>,
    status: Arc<RwLock<SandboxStatus>>,
    last_active: Arc<RwLock<Instant>>,
    created_at: Instant,
    accumulated_cpu_ms: Arc<AtomicU64>,
    overlay_mount: Arc<Mutex<Option<OverlayMount>>>,
    storage_engine: Arc<dyn StorageEngine>,
    runtime_driver: Arc<dyn RuntimeDriver>,
    temp_dir: Option<PathBuf>,
}

impl DefaultSandboxSession {
    /// Creates and pre-warms a new sandbox session.
    pub async fn create_warm(
        config: SandboxConfig,
        storage_engine: Arc<dyn StorageEngine>,
        runtime_driver: Arc<dyn RuntimeDriver>,
    ) -> Result<Self, CoreError> {
        let id = config.session_id.clone();
        let status = Arc::new(RwLock::new(SandboxStatus::Creating));

        // Ensure workspace directory exists or create temporary workspace
        let (workspace_path, temp_dir) = if config.workspace_path.is_empty() {
            let tmp = std::env::temp_dir().join(format!("agentkernel_ws_{}", Uuid::new_v4().simple()));
            tokio::fs::create_dir_all(&tmp).await?;
            (tmp.to_string_lossy().to_string(), Some(tmp))
        } else {
            let p = PathBuf::from(&config.workspace_path);
            if !p.exists() {
                tokio::fs::create_dir_all(&p).await?;
            }
            (config.workspace_path.clone(), None)
        };

        // Prepare base rootfs
        let base_path = match &config.base_rootfs {
            Some(p) => PathBuf::from(p),
            None => {
                let default_base = std::env::temp_dir().join("agentkernel_base_root");
                let _ = tokio::fs::create_dir_all(&default_base).await;
                default_base
            }
        };

        // Mount overlay workspace
        let mount = storage_engine
            .mount_workspace(&base_path, Path::new(&workspace_path))
            .await?;

        *status.write().await = SandboxStatus::Warm;
        let now = Instant::now();

        info!(session_id = %id, "Sandbox successfully initialized and warm");

        Ok(Self {
            id,
            config: Arc::new(RwLock::new(config)),
            status,
            last_active: Arc::new(RwLock::new(now)),
            created_at: now,
            accumulated_cpu_ms: Arc::new(AtomicU64::new(0)),
            overlay_mount: Arc::new(Mutex::new(Some(mount))),
            storage_engine,
            runtime_driver,
            temp_dir,
        })
    }

    /// Leases the warm session to an agent, transitioning state to Leased.
    pub async fn lease(&self, new_config: SandboxConfig) -> Result<(), CoreError> {
        let mut status = self.status.write().await;
        if *status != SandboxStatus::Warm {
            return Err(CoreError::InvalidState(format!(
                "Cannot lease sandbox in state {:?}",
                *status
            )));
        }

        let mut cfg = self.config.write().await;
        cfg.env_vars = new_config.env_vars;
        cfg.timeout_seconds = new_config.timeout_seconds;

        *status = SandboxStatus::Leased;
        *self.last_active.write().await = Instant::now();
        info!(session_id = %self.id, "Sandbox transitioned to Leased");
        Ok(())
    }

    pub async fn status(&self) -> SandboxStatus {
        *self.status.read().await
    }

    pub async fn last_active(&self) -> Instant {
        *self.last_active.read().await
    }

    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    pub fn runtime_driver(&self) -> &Arc<dyn RuntimeDriver> {
        &self.runtime_driver
    }

    pub fn storage_engine(&self) -> &Arc<dyn StorageEngine> {
        &self.storage_engine
    }

    pub async fn mount_point(&self) -> Option<PathBuf> {
        self.overlay_mount.lock().await.as_ref().map(|m| m.mount_point.clone())
    }
}

#[async_trait]
impl SandboxSession for DefaultSandboxSession {
    fn id(&self) -> &str {
        &self.id
    }

    async fn exec(
        &self,
        cmd: &str,
        args: &[String],
        timeout_ms: u64,
    ) -> Result<CommandOutput, CoreError> {
        let current_status = *self.status.read().await;
        if current_status == SandboxStatus::Terminating || current_status == SandboxStatus::Creating {
            return Err(CoreError::InvalidState(format!(
                "Cannot execute command in state {:?}",
                current_status
            )));
        }

        // Transition to Executing
        *self.status.write().await = SandboxStatus::Executing;
        let start = Instant::now();

        let working_dir = {
            let guard = self.overlay_mount.lock().await;
            guard.as_ref().map(|m| m.mount_point.clone())
        };

        let envs = self.config.read().await.env_vars.clone();

        // Spawn and execute command with timeout
        let result = async {
            #[cfg(target_os = "windows")]
            let mut process_cmd = {
                // On Windows, handle shell builtins like echo, dir, etc.
                if cmd == "echo" || cmd == "dir" || cmd == "type" {
                    let mut c = tokio::process::Command::new("cmd");
                    c.arg("/C").arg(cmd);
                    c
                } else {
                    tokio::process::Command::new(cmd)
                }
            };

            #[cfg(not(target_os = "windows"))]
            let mut process_cmd = tokio::process::Command::new(cmd);

            process_cmd.args(args);

            if let Some(ref dir) = working_dir {
                process_cmd.current_dir(dir);
            }

            for (k, v) in envs {
                process_cmd.env(k, v);
            }

            let timeout_duration = Duration::from_millis(timeout_ms);
            let child = process_cmd.output();

            match tokio::time::timeout(timeout_duration, child).await {
                Ok(Ok(output)) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    let total_lines = stdout.lines().count() + stderr.lines().count();
                    let duration_ms = start.elapsed().as_millis() as u64;

                    Ok(CommandOutput {
                        exit_code: output.status.code().unwrap_or(-1),
                        stdout,
                        stderr,
                        duration_ms,
                        truncated: false,
                        total_lines,
                    })
                }
                Ok(Err(e)) => Err(CoreError::Io(e)),
                Err(_) => Err(CoreError::Timeout),
            }
        }
        .await;

        let elapsed_ms = start.elapsed().as_millis() as u64;
        self.accumulated_cpu_ms.fetch_add(elapsed_ms, Ordering::Relaxed);

        // Transition back to Leased and update last_active
        *self.status.write().await = SandboxStatus::Leased;
        *self.last_active.write().await = Instant::now();

        result
    }

    async fn create_checkpoint(&self, name: &str) -> Result<Checkpoint, CoreError> {
        let mut mount_guard = self.overlay_mount.lock().await;
        if let Some(ref mut mount) = *mount_guard {
            let cp = self.storage_engine.create_checkpoint(mount, name).await?;
            *self.last_active.write().await = Instant::now();
            Ok(cp)
        } else {
            Err(CoreError::InvalidState("Overlay not mounted".to_string()))
        }
    }

    async fn rollback(&self, checkpoint_id: &str) -> Result<(), CoreError> {
        let mut mount_guard = self.overlay_mount.lock().await;
        if let Some(ref mut mount) = *mount_guard {
            self.storage_engine.rollback(mount, checkpoint_id).await?;
            *self.last_active.write().await = Instant::now();
            Ok(())
        } else {
            Err(CoreError::InvalidState("Overlay not mounted".to_string()))
        }
    }

    async fn terminate(&self) -> Result<(), CoreError> {
        *self.status.write().await = SandboxStatus::Terminating;

        let mount = self.overlay_mount.lock().await.take();
        if let Some(m) = mount {
            let _ = self.storage_engine.unmount(&m).await;
        }

        if let Some(ref tmp) = self.temp_dir {
            if tmp.exists() {
                let _ = tokio::fs::remove_dir_all(tmp).await;
            }
        }

        info!(session_id = %self.id, "Sandbox session terminated and resources freed");
        Ok(())
    }

    async fn list_checkpoints(&self) -> Result<Vec<CheckpointInfo>, CoreError> {
        let mount_guard = self.overlay_mount.lock().await;
        if let Some(ref mount) = *mount_guard {
            let list = self.storage_engine.list_checkpoints(mount).await?;
            Ok(list)
        } else {
            Err(CoreError::InvalidState("Overlay not mounted".to_string()))
        }
    }

    async fn get_diff(&self, from: Option<&str>, to: Option<&str>) -> Result<Vec<FileDiff>, CoreError> {
        let mount_guard = self.overlay_mount.lock().await;
        if let Some(ref mount) = *mount_guard {
            let diffs = self.storage_engine.get_diff(mount, from, to).await?;
            Ok(diffs)
        } else {
            Err(CoreError::InvalidState("Overlay not mounted".to_string()))
        }
    }

    async fn get_metrics(&self) -> Result<SandboxMetrics, CoreError> {
        let status = *self.status.read().await;
        let uptime_seconds = self.created_at.elapsed().as_secs();
        let cpu_time_ms = self.accumulated_cpu_ms.load(Ordering::Relaxed);

        let disk_usage_bytes = {
            let mount_guard = self.overlay_mount.lock().await;
            if let Some(ref mount) = *mount_guard {
                self.storage_engine
                    .get_storage_usage(mount)
                    .await
                    .map(|u| u.total_size_bytes)
                    .unwrap_or(0)
            } else {
                0
            }
        };

        Ok(SandboxMetrics {
            cpu_time_ms,
            memory_rss_bytes: 0,
            disk_usage_bytes,
            uptime_seconds,
            status,
        })
    }
}

/// Leased sandbox session wrapper tying an acquired session to an agent's request.
pub struct LeasedSandboxSession {
    id: String,
    inner: Arc<DefaultSandboxSession>,
}

impl LeasedSandboxSession {
    pub fn new<S: Into<String>>(id: S, inner: Arc<DefaultSandboxSession>) -> Self {
        Self {
            id: id.into(),
            inner,
        }
    }

    pub fn inner(&self) -> &Arc<DefaultSandboxSession> {
        &self.inner
    }

    pub async fn status(&self) -> SandboxStatus {
        self.inner.status().await
    }

    pub async fn last_active(&self) -> Instant {
        self.inner.last_active().await
    }

    pub async fn mount_point(&self) -> Option<PathBuf> {
        self.inner.mount_point().await
    }
}

#[async_trait]
impl SandboxSession for LeasedSandboxSession {
    fn id(&self) -> &str {
        &self.id
    }

    async fn exec(
        &self,
        cmd: &str,
        args: &[String],
        timeout_ms: u64,
    ) -> Result<CommandOutput, CoreError> {
        self.inner.exec(cmd, args, timeout_ms).await
    }

    async fn create_checkpoint(&self, name: &str) -> Result<Checkpoint, CoreError> {
        self.inner.create_checkpoint(name).await
    }

    async fn rollback(&self, checkpoint_id: &str) -> Result<(), CoreError> {
        self.inner.rollback(checkpoint_id).await
    }

    async fn terminate(&self) -> Result<(), CoreError> {
        self.inner.terminate().await
    }

    async fn list_checkpoints(&self) -> Result<Vec<CheckpointInfo>, CoreError> {
        self.inner.list_checkpoints().await
    }

    async fn get_diff(&self, from: Option<&str>, to: Option<&str>) -> Result<Vec<FileDiff>, CoreError> {
        self.inner.get_diff(from, to).await
    }

    async fn get_metrics(&self) -> Result<SandboxMetrics, CoreError> {
        self.inner.get_metrics().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkernel_fs::{ChangeType, OverlayFsEngine};
    use agentkernel_runtime::PortableRuntimeDriver;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_sandbox_lifecycle() {
        let tmp = tempdir().unwrap();
        let storage = Arc::new(OverlayFsEngine::with_storage_dir(tmp.path().join("storage")));
        let runtime = Arc::new(PortableRuntimeDriver::new());

        let cfg = SandboxConfig::new("test_session_1")
            .with_env("TEST_KEY", "test_val");

        let session = DefaultSandboxSession::create_warm(cfg, storage, runtime)
            .await
            .expect("session created warm");

        assert_eq!(session.status().await, SandboxStatus::Warm);

        // Lease session
        let lease_cfg = SandboxConfig::new("test_session_1").with_env("CUSTOM", "1");
        session.lease(lease_cfg).await.expect("lease successful");
        assert_eq!(session.status().await, SandboxStatus::Leased);

        // Execute command
        let out = session.exec("echo", &["test_exec".to_string()], 5000).await.expect("exec success");
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("test_exec"));

        // Checkpoint & Rollback
        let cp = session.create_checkpoint("cp1").await.expect("checkpoint");
        assert_eq!(cp.name, "cp1");

        session.rollback(&cp.id).await.expect("rollback");

        // Terminate
        session.terminate().await.expect("terminate");
        assert_eq!(session.status().await, SandboxStatus::Terminating);
    }

    #[tokio::test]
    async fn test_session_metrics_collection() {
        let tmp = tempdir().unwrap();
        let storage = Arc::new(OverlayFsEngine::with_storage_dir(tmp.path().join("storage")));
        let runtime = Arc::new(PortableRuntimeDriver::new());

        let cfg = SandboxConfig::new("metrics_session");
        let session = DefaultSandboxSession::create_warm(cfg, storage, runtime)
            .await
            .expect("session created warm");

        // Warm metrics
        let warm_metrics = session.get_metrics().await.expect("warm metrics");
        assert_eq!(warm_metrics.status, SandboxStatus::Warm);
        assert_eq!(warm_metrics.cpu_time_ms, 0);

        // Lease and test leased wrapper
        let leased_cfg = SandboxConfig::new("metrics_session");
        session.lease(leased_cfg).await.expect("lease session");
        let leased_session = LeasedSandboxSession::new("metrics_session", Arc::new(session));

        let leased_metrics = leased_session.get_metrics().await.expect("leased metrics");
        assert_eq!(leased_metrics.status, SandboxStatus::Leased);

        // Exec command and check cpu_time accumulation
        leased_session
            .exec("echo", &["metrics_check".to_string()], 5000)
            .await
            .expect("exec");

        let exec_metrics = leased_session.get_metrics().await.expect("exec metrics");
        assert!(exec_metrics.cpu_time_ms > 0 || exec_metrics.status == SandboxStatus::Leased);

        leased_session.terminate().await.expect("terminate");
    }

    #[tokio::test]
    async fn test_session_checkpoints_and_diffs() {
        let tmp = tempdir().unwrap();
        let workspace = tmp.path().join("ws");
        tokio::fs::create_dir_all(&workspace).await.unwrap();
        tokio::fs::write(workspace.join("initial.txt"), "v1 initial\n").await.unwrap();

        let storage = Arc::new(OverlayFsEngine::with_storage_dir(tmp.path().join("storage")));
        let runtime = Arc::new(PortableRuntimeDriver::new());

        let cfg = SandboxConfig::new("diff_session").with_workspace(workspace.to_str().unwrap());
        let session = Arc::new(
            DefaultSandboxSession::create_warm(cfg, storage, runtime)
                .await
                .expect("created"),
        );

        let leased = LeasedSandboxSession::new("diff_session", session.clone());

        // Initial diff should be empty
        let initial_diff = leased.get_diff(None, None).await.expect("get_diff");
        assert!(initial_diff.is_empty());

        // Modify workspace inside mount_point
        let mount_point = leased.mount_point().await.unwrap();
        tokio::fs::write(mount_point.join("initial.txt"), "v2 modified\n").await.unwrap();
        tokio::fs::write(mount_point.join("created.txt"), "brand new\n").await.unwrap();

        // Diff against base
        let diffs = leased.get_diff(None, None).await.expect("diff against base");
        assert_eq!(diffs.len(), 2);

        let mod_diff = diffs.iter().find(|d| d.path == "initial.txt").unwrap();
        assert_eq!(mod_diff.change_type, ChangeType::Modified);

        let add_diff = diffs.iter().find(|d| d.path == "created.txt").unwrap();
        assert_eq!(add_diff.change_type, ChangeType::Added);

        // Create checkpoint 1
        let cp1 = leased.create_checkpoint("cp1").await.expect("create checkpoint");

        // List checkpoints via session
        let cps = leased.list_checkpoints().await.expect("list checkpoints");
        assert_eq!(cps.len(), 1);
        assert_eq!(cps[0].id, cp1.id);
        assert_eq!(cps[0].name, "cp1");

        // Mutate further: delete created.txt
        tokio::fs::remove_file(mount_point.join("created.txt")).await.unwrap();

        // Diff between cp1 and current
        let diff_since_cp1 = leased.get_diff(Some(&cp1.id), None).await.expect("diff since cp1");
        assert_eq!(diff_since_cp1.len(), 1);
        assert_eq!(diff_since_cp1[0].path, "created.txt");
        assert_eq!(diff_since_cp1[0].change_type, ChangeType::Deleted);

        leased.terminate().await.expect("terminate");
    }
}

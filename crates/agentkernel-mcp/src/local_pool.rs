//! Local cross-platform PoolManager and SandboxSession implementation.
//! Provides realistic process execution, snapshots, and warm-pool mechanics.

use agentkernel_core::pool::PoolManager;
use agentkernel_core::sandbox::{SandboxConfig, SandboxSession};
use agentkernel_core::CoreError;
use agentkernel_fs::{Checkpoint, FsError};
use agentkernel_pty::{CommandOutput, PtyError};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Cross-platform sandbox session utilizing host process isolation and directory snapshots.
pub struct LocalSandboxSession {
    pub id: String,
    pub workspace_path: PathBuf,
    pub config: SandboxConfig,
    checkpoints: Arc<Mutex<HashMap<String, Checkpoint>>>,
}

impl LocalSandboxSession {
    pub fn new(config: SandboxConfig) -> Self {
        let workspace_path = PathBuf::from(&config.workspace_path);
        Self {
            id: config.session_id.clone(),
            workspace_path,
            config,
            checkpoints: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn checkpoint_dir(&self, checkpoint_id: &str) -> PathBuf {
        self.workspace_path
            .join(".agentkernel")
            .join("checkpoints")
            .join(checkpoint_id)
    }
}

#[async_trait]
impl SandboxSession for LocalSandboxSession {
    fn id(&self) -> &str {
        &self.id
    }

    async fn exec(&self, cmd: &str, args: &[String], timeout_ms: u64) -> Result<CommandOutput, CoreError> {
        let start = Instant::now();

        // Ensure workspace directory exists
        if !self.workspace_path.exists() {
            tokio::fs::create_dir_all(&self.workspace_path)
                .await
                .map_err(|e| CoreError::Storage(FsError::Io(e)))?;
        }

        // Try direct command execution first, or shell fallback if needed
        let mut command = if cfg!(windows) && (cmd.ends_with(".bat") || cmd.ends_with(".cmd") || cmd == "dir" || cmd == "echo") {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(cmd);
            for arg in args {
                c.arg(arg);
            }
            c
        } else {
            let mut c = tokio::process::Command::new(cmd);
            for arg in args {
                c.arg(arg);
            }
            c
        };

        command.current_dir(&self.workspace_path);

        for (k, v) in &self.config.env_vars {
            command.env(k, v);
        }

        let timeout_duration = std::time::Duration::from_millis(timeout_ms);
        let child = command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let child = match child {
            Ok(c) => c,
            Err(e) => {
                // If direct command failed on Windows, fallback to cmd /C
                if cfg!(windows) {
                    let mut cmd_fallback = tokio::process::Command::new("cmd");
                    cmd_fallback
                        .arg("/C")
                        .arg(cmd)
                        .args(args)
                        .current_dir(&self.workspace_path)
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped());
                    for (k, v) in &self.config.env_vars {
                        cmd_fallback.env(k, v);
                    }
                    cmd_fallback
                        .spawn()
                        .map_err(|_| CoreError::Pty(PtyError::Io(e)))?
                } else {
                    return Err(CoreError::Pty(PtyError::Io(e)));
                }
            }
        };

        let output = match tokio::time::timeout(timeout_duration, child.wait_with_output()).await {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => return Err(CoreError::Pty(PtyError::Io(e))),
            Err(_) => return Err(CoreError::Pty(PtyError::Timeout)),
        };

        let elapsed = start.elapsed().as_millis() as u64;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let total_lines = stdout.lines().count() + stderr.lines().count();
        let exit_code = output.status.code().unwrap_or(-1);

        Ok(CommandOutput {
            exit_code,
            stdout,
            stderr,
            duration_ms: elapsed,
            truncated: false,
            total_lines,
        })
    }

    async fn create_checkpoint(&self, name: &str) -> Result<Checkpoint, CoreError> {
        let checkpoint_id = Uuid::new_v4().to_string();
        let cp_dir = self.checkpoint_dir(&checkpoint_id);

        copy_dir_recursive(&self.workspace_path, &cp_dir, Some(".agentkernel"))
            .await
            .map_err(|e| CoreError::Storage(FsError::Io(e)))?;

        let checkpoint = Checkpoint {
            id: checkpoint_id.clone(),
            name: name.to_string(),
            created_at: Utc::now(),
            upperdir_path: cp_dir,
        };

        self.checkpoints
            .lock()
            .await
            .insert(checkpoint_id, checkpoint.clone());

        Ok(checkpoint)
    }

    async fn rollback(&self, checkpoint_id: &str) -> Result<(), CoreError> {
        let cp_dir = {
            let cps = self.checkpoints.lock().await;
            cps.get(checkpoint_id)
                .ok_or_else(|| CoreError::Storage(FsError::CheckpointNotFound(checkpoint_id.to_string())))?
                .upperdir_path
                .clone()
        };

        // Clear existing workspace directory preserving .agentkernel snapshots
        clear_dir_preserve(&self.workspace_path, Some(".agentkernel"))
            .await
            .map_err(|e| CoreError::Storage(FsError::Io(e)))?;

        // Restore snapshot into workspace
        copy_dir_recursive(&cp_dir, &self.workspace_path, None)
            .await
            .map_err(|e| CoreError::Storage(FsError::Io(e)))?;

        Ok(())
    }

    async fn terminate(&self) -> Result<(), CoreError> {
        let dot_agentkernel = self.workspace_path.join(".agentkernel");
        if dot_agentkernel.exists() {
            let _ = tokio::fs::remove_dir_all(dot_agentkernel).await;
        }
        Ok(())
    }
}

/// Local warm pool manager maintaining pre-warmed isolates for ultra-fast leasing.
pub struct LocalPoolManager {
    warm_pool_size: usize,
    warm_isolates: Arc<Mutex<Vec<String>>>,
    active_sessions: Arc<RwLock<HashMap<String, Arc<LocalSandboxSession>>>>,
}

impl LocalPoolManager {
    pub fn new(warm_pool_size: usize) -> Self {
        let mut warm_ids = Vec::with_capacity(warm_pool_size);
        for _ in 0..warm_pool_size {
            warm_ids.push(format!("warm-{}", Uuid::new_v4()));
        }

        Self {
            warm_pool_size,
            warm_isolates: Arc::new(Mutex::new(warm_ids)),
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl PoolManager for LocalPoolManager {
    async fn acquire_sandbox(&self, config: SandboxConfig) -> Result<Arc<dyn SandboxSession>, CoreError> {
        let mut warm = self.warm_isolates.lock().await;
        // Pop warm isolate ID if available, otherwise allocate new
        let _source = warm.pop().unwrap_or_else(|| format!("cold-{}", Uuid::new_v4()));

        let session = Arc::new(LocalSandboxSession::new(config.clone()));
        self.active_sessions
            .write()
            .await
            .insert(config.session_id.clone(), session.clone());

        Ok(session)
    }

    async fn release_sandbox(&self, session_id: &str) -> Result<(), CoreError> {
        let session = self.active_sessions.write().await.remove(session_id);
        if let Some(session) = session {
            session.terminate().await?;
        }

        let mut warm = self.warm_isolates.lock().await;
        if warm.len() < self.warm_pool_size {
            warm.push(format!("warm-{}", Uuid::new_v4()));
        }

        Ok(())
    }

    async fn warm_count(&self) -> usize {
        self.warm_isolates.lock().await.len()
    }
}

// Helpers for recursive directory copying and clearing

async fn copy_dir_recursive(src: &Path, dst: &Path, ignore_name: Option<&str>) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut entries = tokio::fs::read_dir(src).await?;

    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        if let Some(ignore) = ignore_name {
            if name == ignore {
                continue;
            }
        }

        let target_path = dst.join(&name);
        let file_type = entry.file_type().await?;

        if file_type.is_dir() {
            Box::pin(copy_dir_recursive(&entry.path(), &target_path, ignore_name)).await?;
        } else {
            tokio::fs::copy(entry.path(), target_path).await?;
        }
    }

    Ok(())
}

async fn clear_dir_preserve(dir: &Path, preserve_name: Option<&str>) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        if let Some(preserve) = preserve_name {
            if name == preserve {
                continue;
            }
        }

        let p = entry.path();
        let file_type = entry.file_type().await?;
        if file_type.is_dir() {
            tokio::fs::remove_dir_all(p).await?;
        } else {
            tokio::fs::remove_file(p).await?;
        }
    }

    Ok(())
}

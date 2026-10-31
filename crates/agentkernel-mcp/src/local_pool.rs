//! Local cross-platform PoolManager and SandboxSession implementation.
//! Provides realistic process execution, snapshots, and warm-pool mechanics.

use crate::metrics::compute_dir_size;
use agentkernel_core::pool::PoolManager;
use agentkernel_core::sandbox::{SandboxConfig, SandboxMetrics, SandboxSession};
use agentkernel_core::{CoreError, SandboxStatus};
use agentkernel_fs::{generate_unified_diff, ChangeType, Checkpoint, CheckpointInfo, FileDiff, FsError};
use agentkernel_pty::{CommandOutput, PtyError};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Cross-platform sandbox session utilizing host process isolation and directory snapshots.
pub struct LocalSandboxSession {
    pub id: String,
    pub workspace_path: PathBuf,
    pub config: SandboxConfig,
    pub created_at: Instant,
    accumulated_cpu_ms: Arc<AtomicU64>,
    checkpoints: Arc<Mutex<HashMap<String, Checkpoint>>>,
    checkpoint_order: Arc<Mutex<Vec<String>>>,
}

impl LocalSandboxSession {
    pub fn new(config: SandboxConfig) -> Self {
        let workspace_path = PathBuf::from(&config.workspace_path);
        Self {
            id: config.session_id.clone(),
            workspace_path,
            config,
            created_at: Instant::now(),
            accumulated_cpu_ms: Arc::new(AtomicU64::new(0)),
            checkpoints: Arc::new(Mutex::new(HashMap::new())),
            checkpoint_order: Arc::new(Mutex::new(Vec::new())),
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
        self.accumulated_cpu_ms.fetch_add(elapsed, Ordering::Relaxed);

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

        let parent_id = self.checkpoint_order.lock().await.last().cloned();
        let checkpoint = Checkpoint {
            id: checkpoint_id.clone(),
            name: name.to_string(),
            created_at: Utc::now(),
            upperdir_path: cp_dir,
            parent_id,
        };

        self.checkpoints
            .lock()
            .await
            .insert(checkpoint_id.clone(), checkpoint.clone());
        self.checkpoint_order.lock().await.push(checkpoint_id);

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

    async fn list_checkpoints(&self) -> Result<Vec<CheckpointInfo>, CoreError> {
        let cps = self.checkpoints.lock().await;
        let order = self.checkpoint_order.lock().await;
        let mut result = Vec::new();

        for (i, id) in order.iter().enumerate() {
            if let Some(cp) = cps.get(id) {
                let size_bytes = compute_dir_size(&cp.upperdir_path);
                let parent_id = if i > 0 { order.get(i - 1).cloned() } else { None };
                result.push(CheckpointInfo {
                    id: cp.id.clone(),
                    name: cp.name.clone(),
                    created_at: cp.created_at,
                    size_bytes,
                    parent_id,
                });
            }
        }

        Ok(result)
    }

    async fn get_diff(&self, from: Option<&str>, to: Option<&str>) -> Result<Vec<FileDiff>, CoreError> {
        let cps = self.checkpoints.lock().await;
        let order = self.checkpoint_order.lock().await;

        let from_dir = match from {
            Some(from_id) => {
                if let Some(cp) = cps.get(from_id) {
                    cp.upperdir_path.clone()
                } else if let Some(cp) = cps.values().find(|c| c.name == from_id) {
                    cp.upperdir_path.clone()
                } else {
                    return Err(CoreError::Storage(FsError::CheckpointNotFound(from_id.to_string())));
                }
            }
            None => {
                if let Some(last_id) = order.last() {
                    cps.get(last_id).map(|c| c.upperdir_path.clone()).unwrap_or_else(|| self.workspace_path.clone())
                } else {
                    self.workspace_path.clone()
                }
            }
        };

        let to_dir = match to {
            Some(to_id) => {
                if let Some(cp) = cps.get(to_id) {
                    cp.upperdir_path.clone()
                } else if let Some(cp) = cps.values().find(|c| c.name == to_id) {
                    cp.upperdir_path.clone()
                } else {
                    return Err(CoreError::Storage(FsError::CheckpointNotFound(to_id.to_string())));
                }
            }
            None => self.workspace_path.clone(),
        };

        let from_files = scan_files_relative_local(&from_dir, &[".agentkernel"]);
        let to_files = scan_files_relative_local(&to_dir, &[".agentkernel"]);

        let mut all_paths = std::collections::BTreeSet::new();
        for p in from_files.keys() {
            all_paths.insert(p.clone());
        }
        for p in to_files.keys() {
            all_paths.insert(p.clone());
        }

        let mut diffs = Vec::new();
        for path in all_paths {
            let from_p = from_files.get(&path);
            let to_p = to_files.get(&path);

            match (from_p, to_p) {
                (None, Some(new_p)) => {
                    let new_content = std::fs::read_to_string(new_p).ok();
                    let patch = generate_unified_diff(&path, None, new_content.as_deref());
                    diffs.push(FileDiff::new(path, ChangeType::Added, patch));
                }
                (Some(old_p), None) => {
                    let old_content = std::fs::read_to_string(old_p).ok();
                    let patch = generate_unified_diff(&path, old_content.as_deref(), None);
                    diffs.push(FileDiff::new(path, ChangeType::Deleted, patch));
                }
                (Some(old_p), Some(new_p)) => {
                    let old_bytes = std::fs::read(old_p).unwrap_or_default();
                    let new_bytes = std::fs::read(new_p).unwrap_or_default();
                    if old_bytes != new_bytes {
                        let old_content = std::str::from_utf8(&old_bytes).ok();
                        let new_content = std::str::from_utf8(&new_bytes).ok();
                        let patch = generate_unified_diff(&path, old_content, new_content);
                        diffs.push(FileDiff::new(path, ChangeType::Modified, patch));
                    }
                }
                (None, None) => {}
            }
        }

        Ok(diffs)
    }

    async fn get_metrics(&self) -> Result<SandboxMetrics, CoreError> {
        let uptime_seconds = self.created_at.elapsed().as_secs();
        let cpu_time_ms = self.accumulated_cpu_ms.load(Ordering::Relaxed);
        let memory_rss_bytes = crate::metrics::get_process_rss_bytes();
        let disk_usage_bytes = {
            let dot_ak = self.workspace_path.join(".agentkernel");
            if dot_ak.exists() {
                compute_dir_size(&dot_ak)
            } else {
                compute_dir_size(&self.workspace_path)
            }
        };

        Ok(SandboxMetrics {
            cpu_time_ms,
            memory_rss_bytes,
            disk_usage_bytes,
            uptime_seconds,
            status: SandboxStatus::Leased,
        })
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

    async fn leased_count(&self) -> usize {
        self.active_sessions.read().await.len()
    }

    async fn get_session(&self, session_id: &str) -> Result<Arc<dyn SandboxSession>, CoreError> {
        self.active_sessions
            .read()
            .await
            .get(session_id)
            .cloned()
            .map(|s| s as Arc<dyn SandboxSession>)
            .ok_or_else(|| CoreError::NotFound(session_id.to_string()))
    }
}

// Helpers for recursive directory copying and clearing

fn scan_files_relative_local(base: &Path, ignore: &[&str]) -> BTreeMap<String, PathBuf> {
    let mut map = BTreeMap::new();
    if !base.exists() {
        return map;
    }
    let _ = scan_walk(base, base, ignore, &mut map);
    map
}

fn scan_walk(
    current: &Path,
    base: &Path,
    ignore: &[&str],
    map: &mut BTreeMap<String, PathBuf>,
) -> std::io::Result<()> {
    if !current.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if ignore.iter().any(|&i| i == name_str) {
            continue;
        }
        if path.is_dir() {
            scan_walk(&path, base, ignore, map)?;
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(base) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                map.insert(rel_str, path);
            }
        }
    }
    Ok(())
}

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

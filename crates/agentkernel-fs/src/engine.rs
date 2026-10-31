//! Layered OverlayFS Engine implementation with Checkpoints & Instant Rollback.

use crate::diff::{generate_unified_diff, ChangeType, FileDiff};
use crate::utils::{
    collect_files, copy_dir_recursive, dir_size, find_deleted_relative_to_lowers,
    sync_diff_to_upper, wipe_dir_contents,
};
use crate::{Checkpoint, CheckpointInfo, FsError, OverlayMount, StorageEngine, StorageUsage};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
#[cfg(not(target_os = "linux"))]
use tracing::{debug, info};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMeta {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub parent_id: Option<String>,
    pub deleted_files: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OverlayFsEngine {
    base_storage_dir: PathBuf,
    checkpoints: Arc<RwLock<HashMap<String, Checkpoint>>>,
}

impl Default for OverlayFsEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlayFsEngine {
    pub fn new() -> Self {
        let storage = std::env::temp_dir().join("agentkernel_overlay_storage");
        Self::with_storage_dir(storage)
    }

    pub fn with_storage_dir<P: Into<PathBuf>>(dir: P) -> Self {
        let storage = dir.into();
        let _ = fs::create_dir_all(&storage);
        Self {
            base_storage_dir: storage,
            checkpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn base_storage_dir(&self) -> &Path {
        &self.base_storage_dir
    }

    /// Helper to find session directory containing checkpoints and working layers.
    fn get_checkpoints_dir(&self, mount: &OverlayMount) -> PathBuf {
        mount
            .mount_point
            .parent()
            .map(|p| p.join("checkpoints"))
            .unwrap_or_else(|| self.base_storage_dir.join("checkpoints"))
    }

    fn save_checkpoint_meta(&self, checkpoints_dir: &Path, meta: &CheckpointMeta) -> Result<(), FsError> {
        let meta_file = checkpoints_dir.join(format!("{}.meta.json", meta.id));
        let json = serde_json::to_string_pretty(meta).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
        fs::write(meta_file, json)?;
        Ok(())
    }

    fn load_checkpoint_meta(&self, checkpoints_dir: &Path, checkpoint_id: &str) -> Option<CheckpointMeta> {
        let meta_file = checkpoints_dir.join(format!("{}.meta.json", checkpoint_id));
        if meta_file.exists() {
            if let Ok(content) = fs::read_to_string(&meta_file) {
                return serde_json::from_str(&content).ok();
            }
        }
        None
    }

    fn resolve_base_files(&self, mount: &OverlayMount) -> Result<HashMap<String, Vec<u8>>, FsError> {
        let mut files = HashMap::new();
        // Lower dirs: workspace [0] has priority over base_root [1].
        // Reverse iteration so that higher priority entries overwrite lower priority entries.
        for lower in mount.lower_dirs.iter().rev() {
            let collected = collect_files(lower, &[".agentkernel"])?;
            files.extend(collected);
        }
        Ok(files)
    }

    fn resolve_current_files(&self, mount: &OverlayMount) -> Result<HashMap<String, Vec<u8>>, FsError> {
        collect_files(&mount.mount_point, &[".agentkernel", ".checkpoint"]).map_err(FsError::Io)
    }

    async fn resolve_checkpoint_files(
        &self,
        mount: &OverlayMount,
        checkpoint_id: &str,
    ) -> Result<HashMap<String, Vec<u8>>, FsError> {
        let checkpoints_dir = self.get_checkpoints_dir(mount);
        let cp = {
            let guard = self.checkpoints.read().await;
            guard.get(checkpoint_id).cloned()
        };

        let (cp_upper, meta) = match cp {
            Some(c) => {
                let meta = self.load_checkpoint_meta(&checkpoints_dir, checkpoint_id);
                (c.upperdir_path, meta)
            }
            None => {
                let cp_dir = checkpoints_dir.join(checkpoint_id);
                if cp_dir.exists() {
                    let meta = self.load_checkpoint_meta(&checkpoints_dir, checkpoint_id);
                    (cp_dir, meta)
                } else {
                    return Err(FsError::CheckpointNotFound(checkpoint_id.to_string()));
                }
            }
        };

        let mut files = self.resolve_base_files(mount)?;

        // Remove deleted files recorded in checkpoint metadata
        if let Some(ref m) = meta {
            for del in &m.deleted_files {
                files.remove(del);
            }
        }

        // Overlay checkpoint upper files
        let upper_files = collect_files(&cp_upper, &[".agentkernel", ".checkpoint_meta.json"])?;
        files.extend(upper_files);

        Ok(files)
    }
}

#[async_trait]
impl StorageEngine for OverlayFsEngine {
    async fn mount_workspace(
        &self,
        base_root: &Path,
        workspace: &Path,
    ) -> Result<OverlayMount, FsError> {
        let session_id = format!("sess_{}", Uuid::new_v4().simple());
        let session_dir = self.base_storage_dir.join(&session_id);

        let mount_point = session_dir.join("merged");
        let active_upper = session_dir.join("upper");
        let work_dir = session_dir.join("work");
        let checkpoints_dir = session_dir.join("checkpoints");

        fs::create_dir_all(&mount_point)?;
        fs::create_dir_all(&active_upper)?;
        fs::create_dir_all(&work_dir)?;
        fs::create_dir_all(&checkpoints_dir)?;

        // lower_dirs: workspace layer has priority over base_root layer
        let lower_dirs = vec![workspace.to_path_buf(), base_root.to_path_buf()];

        #[cfg(target_os = "linux")]
        {
            use nix::mount::MsFlags;

            // OverlayFS lowerdir option syntax expects lowerdir=layer1:layer2
            let opts = format!(
                "lowerdir={}:{},upperdir={},workdir={}",
                workspace.display(),
                base_root.display(),
                active_upper.display(),
                work_dir.display()
            );

            let mnt_res = nix::mount::mount(
                Some("overlay"),
                &mount_point,
                Some("overlay"),
                MsFlags::empty(),
                Some(opts.as_str()),
            );

            if let Err(e) = mnt_res {
                warn!(
                    "Kernel overlay mount failed ({}), falling back to user-space layer emulation",
                    e
                );
                // Fallback to emulated layered mount
                copy_dir_recursive(base_root, &mount_point)?;
                copy_dir_recursive(workspace, &mount_point)?;
            } else {
                info!(mount_point = ?mount_point, "Linux kernel OverlayFS mounted successfully");
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Portable layered emulation: base_root then workspace copied into merged mount_point
            copy_dir_recursive(base_root, &mount_point)?;
            copy_dir_recursive(workspace, &mount_point)?;
            debug!(mount_point = ?mount_point, "Portable layered workspace initialized");
        }

        Ok(OverlayMount {
            mount_point,
            lower_dirs,
            active_upper,
            work_dir,
            current_checkpoint: None,
        })
    }

    async fn create_checkpoint(
        &self,
        mount: &mut OverlayMount,
        name: &str,
    ) -> Result<Checkpoint, FsError> {
        let cp_id = format!("cp_{}_{}", name, Uuid::new_v4().simple());
        let checkpoints_dir = self.get_checkpoints_dir(mount);
        let cp_upper_path = checkpoints_dir.join(&cp_id);
        fs::create_dir_all(&cp_upper_path)?;

        let parent_id = mount.current_checkpoint.clone();
        let deleted_files = find_deleted_relative_to_lowers(&mount.mount_point, &mount.lower_dirs)
            .unwrap_or_default();

        #[cfg(target_os = "linux")]
        {
            // Sync changes from mount_point or active_upper to checkpoint snapshot
            if mount.active_upper.exists() {
                copy_dir_recursive(&mount.active_upper, &cp_upper_path)?;
            }
            // Also sync any diff from merged if running in emulated mode
            sync_diff_to_upper(&mount.mount_point, &mount.lower_dirs, &mount.active_upper)?;
            copy_dir_recursive(&mount.active_upper, &cp_upper_path)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Detect modified or newly created files in mount_point and sync to active_upper
            sync_diff_to_upper(&mount.mount_point, &mount.lower_dirs, &mount.active_upper)?;
            // Snapshot active_upper into checkpoint
            copy_dir_recursive(&mount.active_upper, &cp_upper_path)?;
        }

        let now = Utc::now();
        let meta = CheckpointMeta {
            id: cp_id.clone(),
            name: name.to_string(),
            created_at: now,
            parent_id: parent_id.clone(),
            deleted_files,
        };
        let _ = self.save_checkpoint_meta(&checkpoints_dir, &meta);

        let checkpoint = Checkpoint {
            id: cp_id.clone(),
            name: name.to_string(),
            created_at: now,
            upperdir_path: cp_upper_path,
            parent_id,
        };

        self.checkpoints
            .write()
            .await
            .insert(cp_id.clone(), checkpoint.clone());

        mount.current_checkpoint = Some(cp_id.clone());

        info!(checkpoint_id = %cp_id, name = %name, "Overlay checkpoint created");
        Ok(checkpoint)
    }

    async fn rollback(&self, mount: &mut OverlayMount, checkpoint_id: &str) -> Result<(), FsError> {
        let cp = {
            let guard = self.checkpoints.read().await;
            guard.get(checkpoint_id).cloned()
        };

        let checkpoints_dir = self.get_checkpoints_dir(mount);

        // If not in memory map, try checking disk under checkpoints dir
        let checkpoint = match cp {
            Some(c) => c,
            None => {
                let cp_path = checkpoints_dir.join(checkpoint_id);
                if cp_path.exists() {
                    let meta = self.load_checkpoint_meta(&checkpoints_dir, checkpoint_id);
                    Checkpoint {
                        id: checkpoint_id.to_string(),
                        name: meta.as_ref().map(|m| m.name.clone()).unwrap_or_else(|| checkpoint_id.to_string()),
                        created_at: meta.as_ref().map(|m| m.created_at).unwrap_or_else(Utc::now),
                        upperdir_path: cp_path,
                        parent_id: meta.and_then(|m| m.parent_id),
                    }
                } else {
                    return Err(FsError::CheckpointNotFound(checkpoint_id.to_string()));
                }
            }
        };

        let meta = self.load_checkpoint_meta(&checkpoints_dir, checkpoint_id);

        #[cfg(target_os = "linux")]
        {
            use nix::mount::{umount2, MntFlags, MsFlags};

            // Attempt unmount if native overlay was mounted
            let _ = umount2(&mount.mount_point, MntFlags::MNT_DETACH);

            // Wipe upper and work directories
            wipe_dir_contents(&mount.active_upper)?;
            wipe_dir_contents(&mount.work_dir)?;
            wipe_dir_contents(&mount.mount_point)?;

            // Restore upper from checkpoint snapshot
            copy_dir_recursive(&checkpoint.upperdir_path, &mount.active_upper)?;

            // Check if we can remount kernel overlay
            let workspace = &mount.lower_dirs[0];
            let base_root = &mount.lower_dirs[1];
            let opts = format!(
                "lowerdir={}:{},upperdir={},workdir={}",
                workspace.display(),
                base_root.display(),
                mount.active_upper.display(),
                mount.work_dir.display()
            );

            let remount_res = nix::mount::mount(
                Some("overlay"),
                &mount.mount_point,
                Some("overlay"),
                MsFlags::empty(),
                Some(opts.as_str()),
            );

            if remount_res.is_err() {
                // Emulated fallback restore
                copy_dir_recursive(base_root, &mount.mount_point)?;
                copy_dir_recursive(workspace, &mount.mount_point)?;
                copy_dir_recursive(&checkpoint.upperdir_path, &mount.mount_point)?;

                if let Some(ref m) = meta {
                    for del in &m.deleted_files {
                        let p = mount.mount_point.join(del);
                        if p.exists() {
                            let _ = fs::remove_file(p);
                        }
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Wipe mount_point and active_upper
            wipe_dir_contents(&mount.mount_point)?;
            wipe_dir_contents(&mount.active_upper)?;

            // Re-apply base lower layer
            if let Some(base_root) = mount.lower_dirs.get(1) {
                copy_dir_recursive(base_root, &mount.mount_point)?;
            }
            // Re-apply workspace lower layer
            if let Some(workspace) = mount.lower_dirs.first() {
                copy_dir_recursive(workspace, &mount.mount_point)?;
            }
            // Apply checkpoint snapshot on top
            copy_dir_recursive(&checkpoint.upperdir_path, &mount.active_upper)?;
            copy_dir_recursive(&checkpoint.upperdir_path, &mount.mount_point)?;

            // Remove any files that were recorded as deleted in this checkpoint
            if let Some(ref m) = meta {
                for del in &m.deleted_files {
                    let p = mount.mount_point.join(del);
                    if p.exists() {
                        let _ = fs::remove_file(p);
                    }
                }
            }
        }

        mount.current_checkpoint = Some(checkpoint_id.to_string());
        info!(checkpoint_id = %checkpoint_id, "Overlay filesystem rolled back to checkpoint");
        Ok(())
    }

    async fn unmount(&self, mount: &OverlayMount) -> Result<(), FsError> {
        #[cfg(target_os = "linux")]
        {
            use nix::mount::{umount2, MntFlags};
            let _ = umount2(&mount.mount_point, MntFlags::MNT_DETACH);
        }

        // Clean up session directory if under storage base
        if let Some(session_dir) = mount.mount_point.parent() {
            if session_dir.starts_with(&self.base_storage_dir) && session_dir.exists() {
                let _ = fs::remove_dir_all(session_dir);
                debug!(session_dir = ?session_dir, "Cleaned up overlay session storage");
            }
        }

        Ok(())
    }

    async fn list_checkpoints(&self, mount: &OverlayMount) -> Result<Vec<CheckpointInfo>, FsError> {
        let checkpoints_dir = self.get_checkpoints_dir(mount);
        let mut cps_map: HashMap<String, CheckpointInfo> = HashMap::new();

        // 1. Read checkpoints stored in memory belonging to this session
        {
            let guard = self.checkpoints.read().await;
            for cp in guard.values() {
                if cp.upperdir_path.starts_with(&checkpoints_dir) {
                    let size_bytes = dir_size(&cp.upperdir_path).unwrap_or(0);
                    let meta = self.load_checkpoint_meta(&checkpoints_dir, &cp.id);
                    cps_map.insert(
                        cp.id.clone(),
                        CheckpointInfo {
                            id: cp.id.clone(),
                            name: cp.name.clone(),
                            created_at: cp.created_at,
                            size_bytes,
                            parent_id: meta.and_then(|m| m.parent_id),
                        },
                    );
                }
            }
        }

        // 2. Discover any checkpoints on disk that may have metadata files
        if checkpoints_dir.exists() {
            if let Ok(entries) = fs::read_dir(&checkpoints_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            if let Ok(meta) = serde_json::from_str::<CheckpointMeta>(&content) {
                                let cp_upper = checkpoints_dir.join(&meta.id);
                                let size_bytes = dir_size(&cp_upper).unwrap_or(0);
                                cps_map.entry(meta.id.clone()).or_insert_with(|| CheckpointInfo {
                                    id: meta.id,
                                    name: meta.name,
                                    created_at: meta.created_at,
                                    size_bytes,
                                    parent_id: meta.parent_id,
                                });
                            }
                        }
                    }
                }
            }
        }

        let mut list: Vec<CheckpointInfo> = cps_map.into_values().collect();
        list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then_with(|| a.id.cmp(&b.id)));
        Ok(list)
    }

    async fn get_storage_usage(&self, mount: &OverlayMount) -> Result<StorageUsage, FsError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = sync_diff_to_upper(&mount.mount_point, &mount.lower_dirs, &mount.active_upper);
        }

        let upperdir_size_bytes = dir_size(&mount.active_upper)?;
        let checkpoints_dir = self.get_checkpoints_dir(mount);
        let checkpoints_size_bytes = dir_size(&checkpoints_dir)?;

        Ok(StorageUsage {
            upperdir_size_bytes,
            checkpoints_size_bytes,
            total_size_bytes: upperdir_size_bytes + checkpoints_size_bytes,
        })
    }

    async fn get_diff(
        &self,
        mount: &OverlayMount,
        from_checkpoint: Option<&str>,
        to_checkpoint: Option<&str>,
    ) -> Result<Vec<FileDiff>, FsError> {
        let from_files = match from_checkpoint {
            None => self.resolve_base_files(mount)?,
            Some(id) => self.resolve_checkpoint_files(mount, id).await?,
        };

        let to_files = match to_checkpoint {
            None => self.resolve_current_files(mount)?,
            Some(id) => self.resolve_checkpoint_files(mount, id).await?,
        };

        let mut all_paths = BTreeSet::new();
        all_paths.extend(from_files.keys().cloned());
        all_paths.extend(to_files.keys().cloned());

        let mut diffs = Vec::new();
        for path in all_paths {
            match (from_files.get(&path), to_files.get(&path)) {
                (None, Some(new_bytes)) => {
                    let new_str = String::from_utf8_lossy(new_bytes);
                    let patch = generate_unified_diff(&path, None, Some(&new_str));
                    diffs.push(FileDiff::new(path, ChangeType::Added, patch));
                }
                (Some(old_bytes), None) => {
                    let old_str = String::from_utf8_lossy(old_bytes);
                    let patch = generate_unified_diff(&path, Some(&old_str), None);
                    diffs.push(FileDiff::new(path, ChangeType::Deleted, patch));
                }
                (Some(old_bytes), Some(new_bytes)) => {
                    if old_bytes != new_bytes {
                        let old_str = String::from_utf8_lossy(old_bytes);
                        let new_str = String::from_utf8_lossy(new_bytes);
                        let patch = generate_unified_diff(&path, Some(&old_str), Some(&new_str));
                        diffs.push(FileDiff::new(path, ChangeType::Modified, patch));
                    }
                }
                (None, None) => {}
            }
        }

        Ok(diffs)
    }
}

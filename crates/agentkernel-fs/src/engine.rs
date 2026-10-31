//! Layered OverlayFS Engine implementation with Checkpoints & Instant Rollback.

use crate::utils::{copy_dir_recursive, sync_diff_to_upper, wipe_dir_contents};
use crate::{Checkpoint, FsError, OverlayMount, StorageEngine};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
#[cfg(not(target_os = "linux"))]
use tracing::{debug, info};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};
use uuid::Uuid;

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
            use nix::mount::{MsFlags};

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

        let checkpoint = Checkpoint {
            id: cp_id.clone(),
            name: name.to_string(),
            created_at: Utc::now(),
            upperdir_path: cp_upper_path,
        };

        self.checkpoints
            .write()
            .await
            .insert(cp_id.clone(), checkpoint.clone());

        info!(checkpoint_id = %cp_id, name = %name, "Overlay checkpoint created");
        Ok(checkpoint)
    }

    async fn rollback(&self, mount: &mut OverlayMount, checkpoint_id: &str) -> Result<(), FsError> {
        let cp = {
            let guard = self.checkpoints.read().await;
            guard.get(checkpoint_id).cloned()
        };

        // If not in memory map, try checking disk under checkpoints dir
        let checkpoint = match cp {
            Some(c) => c,
            None => {
                let checkpoints_dir = self.get_checkpoints_dir(mount);
                let cp_path = checkpoints_dir.join(checkpoint_id);
                if cp_path.exists() {
                    Checkpoint {
                        id: checkpoint_id.to_string(),
                        name: checkpoint_id.to_string(),
                        created_at: Utc::now(),
                        upperdir_path: cp_path,
                    }
                } else {
                    return Err(FsError::CheckpointNotFound(checkpoint_id.to_string()));
                }
            }
        };

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
        }

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
}

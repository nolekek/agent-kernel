//! AgentKernel FS: Layered OverlayFS, CoW Snapshots & Rollback Engine.

pub mod engine;
pub mod utils;

pub use engine::OverlayFsEngine;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Mount failure: {0}")]
    MountFailed(String),
    #[error("Checkpoint not found: {0}")]
    CheckpointNotFound(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub upperdir_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct OverlayMount {
    pub mount_point: PathBuf,
    pub lower_dirs: Vec<PathBuf>,
    pub active_upper: PathBuf,
    pub work_dir: PathBuf,
}

#[async_trait]
pub trait StorageEngine: Send + Sync {
    async fn mount_workspace(&self, base_root: &Path, workspace: &Path) -> Result<OverlayMount, FsError>;
    async fn create_checkpoint(&self, mount: &mut OverlayMount, name: &str) -> Result<Checkpoint, FsError>;
    async fn rollback(&self, mount: &mut OverlayMount, checkpoint_id: &str) -> Result<(), FsError>;
    async fn unmount(&self, mount: &OverlayMount) -> Result<(), FsError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_overlay_mount_workspace() {
        let tmp = tempdir().unwrap();
        let base_root = tmp.path().join("base_root");
        let workspace = tmp.path().join("workspace");
        let storage = tmp.path().join("storage");

        fs::create_dir_all(&base_root).unwrap();
        fs::create_dir_all(&workspace).unwrap();

        fs::write(base_root.join("base_file.txt"), "base content").unwrap();
        fs::write(workspace.join("code.py"), "print('hello world')").unwrap();

        let engine = OverlayFsEngine::with_storage_dir(storage);
        let mount = engine
            .mount_workspace(&base_root, &workspace)
            .await
            .expect("mount should succeed");

        // Verify files in mount_point
        assert!(mount.mount_point.join("base_file.txt").exists());
        assert_eq!(
            fs::read_to_string(mount.mount_point.join("base_file.txt")).unwrap(),
            "base content"
        );
        assert!(mount.mount_point.join("code.py").exists());
        assert_eq!(
            fs::read_to_string(mount.mount_point.join("code.py")).unwrap(),
            "print('hello world')"
        );

        engine.unmount(&mount).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_checkpoint_and_rollback() {
        let tmp = tempdir().unwrap();
        let base_root = tmp.path().join("base_root");
        let workspace = tmp.path().join("workspace");
        let storage = tmp.path().join("storage");

        fs::create_dir_all(&base_root).unwrap();
        fs::create_dir_all(&workspace).unwrap();

        fs::write(base_root.join("config.json"), r#"{"env": "prod"}"#).unwrap();
        fs::write(workspace.join("main.rs"), "fn main() { println!(\"initial\"); }").unwrap();

        let engine = OverlayFsEngine::with_storage_dir(storage);
        let mut mount = engine
            .mount_workspace(&base_root, &workspace)
            .await
            .expect("mount workspace");

        // Step 1: Modify code in mount_point
        fs::write(mount.mount_point.join("main.rs"), "fn main() { println!(\"checkpoint-1\"); }").unwrap();
        fs::write(mount.mount_point.join("new_file.txt"), "new file at cp1").unwrap();

        // Step 2: Create checkpoint 1
        let cp1 = engine
            .create_checkpoint(&mut mount, "cp_state_1")
            .await
            .expect("checkpoint 1 creation");

        assert_eq!(cp1.name, "cp_state_1");
        assert!(cp1.upperdir_path.exists());

        // Step 3: Modify workspace further (simulating unwanted agent error / corruption)
        fs::write(mount.mount_point.join("main.rs"), "corrupted content syntax error").unwrap();
        fs::write(mount.mount_point.join("rogue.sh"), "rm -rf /").unwrap();

        // Step 4: Perform rollback to checkpoint 1
        engine
            .rollback(&mut mount, &cp1.id)
            .await
            .expect("rollback to cp1");

        // Step 5: Verify mount_point state matches checkpoint 1
        let restored_main = fs::read_to_string(mount.mount_point.join("main.rs")).unwrap();
        assert_eq!(restored_main, "fn main() { println!(\"checkpoint-1\"); }");

        let new_file_content = fs::read_to_string(mount.mount_point.join("new_file.txt")).unwrap();
        assert_eq!(new_file_content, "new file at cp1");

        // Rogue file should NOT exist after rollback
        assert!(!mount.mount_point.join("rogue.sh").exists());

        // Base file should still be preserved
        assert_eq!(
            fs::read_to_string(mount.mount_point.join("config.json")).unwrap(),
            r#"{"env": "prod"}"#
        );

        engine.unmount(&mount).await.unwrap();
    }

    #[tokio::test]
    async fn test_multiple_checkpoints_and_rollback_sequence() {
        let tmp = tempdir().unwrap();
        let base_root = tmp.path().join("base");
        let workspace = tmp.path().join("work");
        let storage = tmp.path().join("storage");

        fs::create_dir_all(&base_root).unwrap();
        fs::create_dir_all(&workspace).unwrap();

        let engine = OverlayFsEngine::with_storage_dir(storage);
        let mut mount = engine.mount_workspace(&base_root, &workspace).await.unwrap();

        // State A
        fs::write(mount.mount_point.join("counter.txt"), "1").unwrap();
        let cp_a = engine.create_checkpoint(&mut mount, "state_a").await.unwrap();

        // State B
        fs::write(mount.mount_point.join("counter.txt"), "2").unwrap();
        let cp_b = engine.create_checkpoint(&mut mount, "state_b").await.unwrap();

        // State C
        fs::write(mount.mount_point.join("counter.txt"), "3").unwrap();

        // Rollback to State B
        engine.rollback(&mut mount, &cp_b.id).await.unwrap();
        assert_eq!(fs::read_to_string(mount.mount_point.join("counter.txt")).unwrap(), "2");

        // Rollback to State A
        engine.rollback(&mut mount, &cp_a.id).await.unwrap();
        assert_eq!(fs::read_to_string(mount.mount_point.join("counter.txt")).unwrap(), "1");

        engine.unmount(&mount).await.unwrap();
    }
}

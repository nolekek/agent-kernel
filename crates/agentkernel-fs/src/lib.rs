//! AgentKernel FS: Layered OverlayFS, CoW Snapshots & Rollback Engine.

pub mod diff;
pub mod engine;
pub mod utils;

pub use diff::{generate_unified_diff, ChangeType, FileDiff};
pub use engine::OverlayFsEngine;
pub use utils::dir_size;

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
    #[serde(default)]
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointInfo {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub size_bytes: u64,
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StorageUsage {
    pub upperdir_size_bytes: u64,
    pub checkpoints_size_bytes: u64,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct OverlayMount {
    pub mount_point: PathBuf,
    pub lower_dirs: Vec<PathBuf>,
    pub active_upper: PathBuf,
    pub work_dir: PathBuf,
    pub current_checkpoint: Option<String>,
}

#[async_trait]
pub trait StorageEngine: Send + Sync {
    async fn mount_workspace(&self, base_root: &Path, workspace: &Path) -> Result<OverlayMount, FsError>;
    async fn create_checkpoint(&self, mount: &mut OverlayMount, name: &str) -> Result<Checkpoint, FsError>;
    async fn rollback(&self, mount: &mut OverlayMount, checkpoint_id: &str) -> Result<(), FsError>;
    async fn unmount(&self, mount: &OverlayMount) -> Result<(), FsError>;
    async fn list_checkpoints(&self, mount: &OverlayMount) -> Result<Vec<CheckpointInfo>, FsError>;
    async fn get_storage_usage(&self, mount: &OverlayMount) -> Result<StorageUsage, FsError>;
    async fn get_diff(
        &self,
        mount: &OverlayMount,
        from_checkpoint: Option<&str>,
        to_checkpoint: Option<&str>,
    ) -> Result<Vec<FileDiff>, FsError>;
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

    #[tokio::test]
    async fn test_list_checkpoints_tree_metadata() {
        let tmp = tempdir().unwrap();
        let base_root = tmp.path().join("base");
        let workspace = tmp.path().join("work");
        let storage = tmp.path().join("storage");

        fs::create_dir_all(&base_root).unwrap();
        fs::create_dir_all(&workspace).unwrap();

        let engine = OverlayFsEngine::with_storage_dir(storage);
        let mut mount = engine.mount_workspace(&base_root, &workspace).await.unwrap();

        // Initially empty
        let initial_cps = engine.list_checkpoints(&mount).await.unwrap();
        assert!(initial_cps.is_empty());

        // Create cp1
        fs::write(mount.mount_point.join("file1.txt"), "hello checkpoint 1").unwrap();
        let cp1 = engine.create_checkpoint(&mut mount, "cp1").await.unwrap();

        // Create cp2
        fs::write(mount.mount_point.join("file2.txt"), "hello checkpoint 2").unwrap();
        let cp2 = engine.create_checkpoint(&mut mount, "cp2").await.unwrap();

        let list = engine.list_checkpoints(&mount).await.unwrap();
        assert_eq!(list.len(), 2);

        assert_eq!(list[0].id, cp1.id);
        assert_eq!(list[0].name, "cp1");
        assert_eq!(list[0].parent_id, None);
        assert!(list[0].size_bytes > 0);

        assert_eq!(list[1].id, cp2.id);
        assert_eq!(list[1].name, "cp2");
        assert_eq!(list[1].parent_id, Some(cp1.id.clone()));
        assert!(list[1].size_bytes > 0);

        // Branching: rollback to cp1 and create cp3
        engine.rollback(&mut mount, &cp1.id).await.unwrap();
        fs::write(mount.mount_point.join("branch.txt"), "branching from cp1").unwrap();
        let cp3 = engine.create_checkpoint(&mut mount, "cp3_branch").await.unwrap();

        let list_after_branch = engine.list_checkpoints(&mount).await.unwrap();
        assert_eq!(list_after_branch.len(), 3);
        let item3 = list_after_branch.iter().find(|c| c.id == cp3.id).unwrap();
        assert_eq!(item3.parent_id, Some(cp1.id.clone()));

        engine.unmount(&mount).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_storage_usage() {
        let tmp = tempdir().unwrap();
        let base_root = tmp.path().join("base");
        let workspace = tmp.path().join("work");
        let storage = tmp.path().join("storage");

        fs::create_dir_all(&base_root).unwrap();
        fs::create_dir_all(&workspace).unwrap();

        let engine = OverlayFsEngine::with_storage_dir(storage);
        let mut mount = engine.mount_workspace(&base_root, &workspace).await.unwrap();

        // Add file to active upper
        let data = "A".repeat(1024); // 1 KB
        fs::write(mount.mount_point.join("data.txt"), &data).unwrap();

        let usage_before_cp = engine.get_storage_usage(&mount).await.unwrap();
        assert!(usage_before_cp.upperdir_size_bytes >= 1024);
        assert_eq!(usage_before_cp.checkpoints_size_bytes, 0);
        assert_eq!(usage_before_cp.total_size_bytes, usage_before_cp.upperdir_size_bytes);

        // Create checkpoint
        let _cp = engine.create_checkpoint(&mut mount, "cp_storage").await.unwrap();

        let usage_after_cp = engine.get_storage_usage(&mount).await.unwrap();
        assert!(usage_after_cp.checkpoints_size_bytes >= 1024);
        assert_eq!(
            usage_after_cp.total_size_bytes,
            usage_after_cp.upperdir_size_bytes + usage_after_cp.checkpoints_size_bytes
        );

        engine.unmount(&mount).await.unwrap();
    }

    #[tokio::test]
    async fn test_diff_added_modified_deleted() {
        let tmp = tempdir().unwrap();
        let base_root = tmp.path().join("base");
        let workspace = tmp.path().join("work");
        let storage = tmp.path().join("storage");

        fs::create_dir_all(&base_root).unwrap();
        fs::create_dir_all(&workspace).unwrap();

        // Initial files in workspace and base
        fs::write(workspace.join("to_modify.txt"), "line 1\nline 2\nline 3\n").unwrap();
        fs::write(workspace.join("to_delete.txt"), "delete me\n").unwrap();

        let engine = OverlayFsEngine::with_storage_dir(storage);
        let mut mount = engine.mount_workspace(&base_root, &workspace).await.unwrap();

        // No changes initially
        let diffs_initial = engine.get_diff(&mount, None, None).await.unwrap();
        assert!(diffs_initial.is_empty());

        // Perform modifications:
        // 1. Add new file
        fs::write(mount.mount_point.join("new_file.txt"), "brand new line\n").unwrap();

        // 2. Modify existing file
        fs::write(
            mount.mount_point.join("to_modify.txt"),
            "line 1\nline 2 modified\nline 3\n",
        )
        .unwrap();

        // 3. Delete file
        fs::remove_file(mount.mount_point.join("to_delete.txt")).unwrap();

        // Check diff between base (None) and current (None)
        let diffs = engine.get_diff(&mount, None, None).await.unwrap();
        assert_eq!(diffs.len(), 3);

        let added_diff = diffs.iter().find(|d| d.path == "new_file.txt").unwrap();
        assert_eq!(added_diff.change_type, ChangeType::Added);
        assert!(added_diff.diff.contains("--- /dev/null"));
        assert!(added_diff.diff.contains("+++ b/new_file.txt"));
        assert!(added_diff.diff.contains("+brand new line"));

        let mod_diff = diffs.iter().find(|d| d.path == "to_modify.txt").unwrap();
        assert_eq!(mod_diff.change_type, ChangeType::Modified);
        assert!(mod_diff.diff.contains("--- a/to_modify.txt"));
        assert!(mod_diff.diff.contains("+++ b/to_modify.txt"));
        assert!(mod_diff.diff.contains("-line 2"));
        assert!(mod_diff.diff.contains("+line 2 modified"));

        let del_diff = diffs.iter().find(|d| d.path == "to_delete.txt").unwrap();
        assert_eq!(del_diff.change_type, ChangeType::Deleted);
        assert!(del_diff.diff.contains("--- a/to_delete.txt"));
        assert!(del_diff.diff.contains("+++ /dev/null"));
        assert!(del_diff.diff.contains("-delete me"));

        // Create checkpoint 1
        let cp1 = engine.create_checkpoint(&mut mount, "cp1_state").await.unwrap();

        // Mutate further: add another file
        fs::write(mount.mount_point.join("file_after_cp1.txt"), "after cp1\n").unwrap();

        // Diff between cp1 and current: should only show file_after_cp1.txt
        let diffs_since_cp1 = engine.get_diff(&mount, Some(&cp1.id), None).await.unwrap();
        assert_eq!(diffs_since_cp1.len(), 1);
        assert_eq!(diffs_since_cp1[0].path, "file_after_cp1.txt");
        assert_eq!(diffs_since_cp1[0].change_type, ChangeType::Added);

        engine.unmount(&mount).await.unwrap();
    }
}

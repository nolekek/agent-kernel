//! Fast directory diff comparator utilizing AgentKernel FS unified diff engine.

use agentkernel_fs::generate_unified_diff;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Result of comparing two directories or snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DirectoryDiff {
    /// List of relative paths for files that were added, removed, or modified.
    pub files: Vec<String>,
    /// Unified diff string containing file headers and hunks.
    pub diff: String,
}

/// Computes unified diff between two directories, skipping specified subdirectories (e.g. `.agentkernel`).
pub fn compute_directory_diff(
    from_dir: &Path,
    to_dir: &Path,
    ignore_subdirs: &[&str],
) -> std::io::Result<DirectoryDiff> {
    let from_files = scan_files_relative(from_dir, ignore_subdirs)?;
    let to_files = scan_files_relative(to_dir, ignore_subdirs)?;

    let mut all_paths: HashSet<String> = HashSet::new();
    for p in from_files.keys() {
        all_paths.insert(p.clone());
    }
    for p in to_files.keys() {
        all_paths.insert(p.clone());
    }

    let mut sorted_paths: Vec<String> = all_paths.into_iter().collect();
    sorted_paths.sort();

    let mut changed_files = Vec::new();
    let mut diff_output = String::new();

    for rel_path in sorted_paths {
        let from_abs = from_files.get(&rel_path);
        let to_abs = to_files.get(&rel_path);

        match (from_abs, to_abs) {
            (Some(fa), Some(fb)) => {
                let bytes_a = fs::read(fa)?;
                let bytes_b = fs::read(fb)?;

                if bytes_a != bytes_b {
                    changed_files.push(rel_path.clone());
                    let old_str = std::str::from_utf8(&bytes_a).ok();
                    let new_str = std::str::from_utf8(&bytes_b).ok();
                    let patch = generate_unified_diff(&rel_path, old_str, new_str);
                    diff_output.push_str(&patch);
                }
            }
            (None, Some(fb)) => {
                let bytes_b = fs::read(fb)?;
                changed_files.push(rel_path.clone());
                let new_str = std::str::from_utf8(&bytes_b).ok();
                let patch = generate_unified_diff(&rel_path, None, new_str);
                diff_output.push_str(&patch);
            }
            (Some(fa), None) => {
                let bytes_a = fs::read(fa)?;
                changed_files.push(rel_path.clone());
                let old_str = std::str::from_utf8(&bytes_a).ok();
                let patch = generate_unified_diff(&rel_path, old_str, None);
                diff_output.push_str(&patch);
            }
            (None, None) => {}
        }
    }

    Ok(DirectoryDiff {
        files: changed_files,
        diff: diff_output,
    })
}

/// Recursively scans directory and returns map of relative path (normalized forward slashes) to PathBuf.
pub fn scan_files_relative(
    base: &Path,
    ignore_subdirs: &[&str],
) -> std::io::Result<BTreeMap<String, PathBuf>> {
    let mut map = BTreeMap::new();
    if !base.exists() {
        return Ok(map);
    }
    scan_dir_walk(base, base, ignore_subdirs, &mut map)?;
    Ok(map)
}

fn scan_dir_walk(
    current: &Path,
    base: &Path,
    ignore_subdirs: &[&str],
    map: &mut BTreeMap<String, PathBuf>,
) -> std::io::Result<()> {
    if !current.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if ignore_subdirs.iter().any(|&ign| ign == name_str) {
            continue;
        }

        if path.is_dir() {
            scan_dir_walk(&path, base, ignore_subdirs, map)?;
        } else if path.is_file() {
            if let Ok(rel) = path.strip_prefix(base) {
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                map.insert(rel_str, path);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_directory_diff() {
        let tmp = tempdir().unwrap();
        let dir_a = tmp.path().join("dir_a");
        let dir_b = tmp.path().join("dir_b");

        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();

        fs::write(dir_a.join("same.txt"), "hello").unwrap();
        fs::write(dir_b.join("same.txt"), "hello").unwrap();

        fs::write(dir_a.join("mod.txt"), "version 1").unwrap();
        fs::write(dir_b.join("mod.txt"), "version 2").unwrap();

        fs::write(dir_b.join("new.txt"), "created").unwrap();

        let diff = compute_directory_diff(&dir_a, &dir_b, &[".agentkernel"]).unwrap();
        assert_eq!(diff.files.len(), 2);
        assert!(diff.files.contains(&"mod.txt".to_string()));
        assert!(diff.files.contains(&"new.txt".to_string()));
        assert!(!diff.files.contains(&"same.txt".to_string()));

        assert!(diff.diff.contains("--- a/mod.txt"));
        assert!(diff.diff.contains("+++ b/mod.txt"));
        assert!(diff.diff.contains("-version 1"));
        assert!(diff.diff.contains("+version 2"));
        assert!(diff.diff.contains("+++ b/new.txt"));
    }
}

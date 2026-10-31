//! Filesystem Utilities: Recursive Copy, Directory Wipe & Layer Diffing.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Recursively copies all entries from `src` to `dst`.
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    if !src.exists() {
        return Ok(());
    }
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target_path)?;
        } else {
            fs::copy(entry.path(), &target_path)?;
        }
    }

    Ok(())
}

/// Wipes all entries inside `dir`, but leaves `dir` intact.
pub fn wipe_dir_contents(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        return fs::create_dir_all(dir);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }

    Ok(())
}

/// Recursively compares `current` against `lower_dirs` and copies all new or modified files to `upper`.
pub fn sync_diff_to_upper(current: &Path, lower_dirs: &[PathBuf], upper: &Path) -> io::Result<()> {
    if !current.exists() {
        return Ok(());
    }
    fs::create_dir_all(upper)?;

    sync_diff_recursive(current, current, lower_dirs, upper)
}

fn sync_diff_recursive(
    root: &Path,
    current: &Path,
    lower_dirs: &[PathBuf],
    upper_root: &Path,
) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(root).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
        })?;

        let upper_dest = upper_root.join(rel_path);

        if entry.file_type()?.is_dir() {
            fs::create_dir_all(&upper_dest)?;
            sync_diff_recursive(root, &path, lower_dirs, upper_root)?;
        } else {
            let is_modified = is_file_modified_relative_to_lowers(rel_path, &path, lower_dirs);
            if is_modified {
                if let Some(parent) = upper_dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&path, &upper_dest)?;
            }
        }
    }

    Ok(())
}

/// Checks whether a file at `current_file` differs in length or contents from any file at `rel_path` in `lower_dirs`.
fn is_file_modified_relative_to_lowers(
    rel_path: &Path,
    current_file: &Path,
    lower_dirs: &[PathBuf],
) -> bool {
    let mut found_in_lower = false;

    for lower in lower_dirs {
        let lower_file = lower.join(rel_path);
        if lower_file.exists() && lower_file.is_file() {
            found_in_lower = true;
            // Compare metadata / contents
            if let (Ok(curr_meta), Ok(lower_meta)) = (current_file.metadata(), lower_file.metadata()) {
                if curr_meta.len() != lower_meta.len() {
                    return true;
                }
                // If same length, verify byte contents
                if let (Ok(curr_bytes), Ok(lower_bytes)) = (fs::read(current_file), fs::read(&lower_file)) {
                    if curr_bytes != lower_bytes {
                        return true;
                    }
                }
            }
            break;
        }
    }

    // If not found in any lower directory, it is a newly created file!
    if !found_in_lower {
        return true;
    }

    false
}

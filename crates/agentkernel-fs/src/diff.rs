//! Unified diff engine and file change types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: String,
    pub change_type: ChangeType,
    pub diff: String,
}

impl FileDiff {
    pub fn new<P: Into<String>, D: Into<String>>(
        path: P,
        change_type: ChangeType,
        diff: D,
    ) -> Self {
        Self {
            path: path.into(),
            change_type,
            diff: diff.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffOp<'a> {
    Equal(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

/// Generates a standard unified diff string for a file.
///
/// If `old_content` is `None`, the file is treated as newly added.
/// If `new_content` is `None`, the file is treated as deleted.
/// If both are `Some`, a standard unified diff with context is generated.
pub fn generate_unified_diff(
    path: &str,
    old_content: Option<&str>,
    new_content: Option<&str>,
) -> String {
    let normalized_path = path.replace('\\', "/");

    match (old_content, new_content) {
        (None, Some(new_str)) => {
            let lines: Vec<&str> = if new_str.is_empty() {
                Vec::new()
            } else {
                new_str.lines().collect()
            };
            let count = lines.len();
            let mut out = String::new();
            out.push_str("--- /dev/null\n");
            out.push_str(&format!("+++ b/{}\n", normalized_path));
            if count == 0 {
                out.push_str("@@ -0,0 +0,0 @@\n");
            } else {
                out.push_str(&format!("@@ -0,0 +1,{} @@\n", count));
                for line in lines {
                    out.push('+');
                    out.push_str(line);
                    out.push('\n');
                }
            }
            out
        }
        (Some(old_str), None) => {
            let lines: Vec<&str> = if old_str.is_empty() {
                Vec::new()
            } else {
                old_str.lines().collect()
            };
            let count = lines.len();
            let mut out = String::new();
            out.push_str(&format!("--- a/{}\n", normalized_path));
            out.push_str("+++ /dev/null\n");
            if count == 0 {
                out.push_str("@@ -0,0 +0,0 @@\n");
            } else {
                out.push_str(&format!("@@ -1,{} +0,0 @@\n", count));
                for line in lines {
                    out.push('-');
                    out.push_str(line);
                    out.push('\n');
                }
            }
            out
        }
        (Some(old_str), Some(new_str)) => {
            if old_str == new_str {
                return String::new();
            }

            let old_lines: Vec<&str> = if old_str.is_empty() {
                Vec::new()
            } else {
                old_str.lines().collect()
            };
            let new_lines: Vec<&str> = if new_str.is_empty() {
                Vec::new()
            } else {
                new_str.lines().collect()
            };

            let ops = compute_diff_ops(&old_lines, &new_lines);
            format_unified_hunks(&normalized_path, &ops, 3)
        }
        (None, None) => String::new(),
    }
}

/// Computes the sequence of diff operations using LCS with prefix/suffix trimming.
fn compute_diff_ops<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<DiffOp<'a>> {
    let mut prefix = 0;
    while prefix < old.len() && prefix < new.len() && old[prefix] == new[prefix] {
        prefix += 1;
    }

    let mut suffix = 0;
    while suffix < (old.len() - prefix)
        && suffix < (new.len() - prefix)
        && old[old.len() - 1 - suffix] == new[new.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let mid_old = &old[prefix..old.len() - suffix];
    let mid_new = &new[prefix..new.len() - suffix];

    let mut ops = Vec::with_capacity(old.len() + new.len());
    for &l in &old[..prefix] {
        ops.push(DiffOp::Equal(l));
    }

    let m = mid_old.len();
    let n = mid_new.len();
    if m > 0 && n > 0 {
        // Dynamic programming table for LCS
        let mut dp = vec![vec![0u32; n + 1]; m + 1];
        for i in 1..=m {
            for j in 1..=n {
                if mid_old[i - 1] == mid_new[j - 1] {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
                }
            }
        }

        // Backtrack to find diff operations
        let mut i = m;
        let mut j = n;
        let mut mid_ops = Vec::new();
        while i > 0 || j > 0 {
            if i > 0 && j > 0 && mid_old[i - 1] == mid_new[j - 1] {
                mid_ops.push(DiffOp::Equal(mid_old[i - 1]));
                i -= 1;
                j -= 1;
            } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
                mid_ops.push(DiffOp::Insert(mid_new[j - 1]));
                j -= 1;
            } else if i > 0 {
                mid_ops.push(DiffOp::Delete(mid_old[i - 1]));
                i -= 1;
            }
        }
        mid_ops.reverse();
        ops.extend(mid_ops);
    } else {
        for &l in mid_old {
            ops.push(DiffOp::Delete(l));
        }
        for &l in mid_new {
            ops.push(DiffOp::Insert(l));
        }
    }

    for &l in &old[old.len() - suffix..] {
        ops.push(DiffOp::Equal(l));
    }

    ops
}

/// Formats diff operations into standard unified diff hunks with context.
fn format_unified_hunks(path: &str, ops: &[DiffOp], context: usize) -> String {
    let change_indices: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter_map(|(idx, op)| match op {
            DiffOp::Delete(_) | DiffOp::Insert(_) => Some(idx),
            DiffOp::Equal(_) => None,
        })
        .collect();

    if change_indices.is_empty() {
        return String::new();
    }

    // Group changes into clusters separated by more than 2 * context
    let mut clusters: Vec<(usize, usize)> = Vec::new();
    let mut cluster_start = change_indices[0].saturating_sub(context);
    let mut cluster_end = (change_indices[0] + context + 1).min(ops.len());

    for &idx in &change_indices[1..] {
        let ch_start = idx.saturating_sub(context);
        let ch_end = (idx + context + 1).min(ops.len());

        if ch_start <= cluster_end {
            cluster_end = cluster_end.max(ch_end);
        } else {
            clusters.push((cluster_start, cluster_end));
            cluster_start = ch_start;
            cluster_end = ch_end;
        }
    }
    clusters.push((cluster_start, cluster_end));

    let mut out = String::new();
    out.push_str(&format!("--- a/{}\n", path));
    out.push_str(&format!("+++ b/{}\n", path));

    // Iterate through ops and generate each hunk with line numbers
    let mut op_idx = 0;
    let mut old_line = 1usize;
    let mut new_line = 1usize;

    for (c_start, c_end) in clusters {
        // Fast-forward line numbers up to c_start
        while op_idx < c_start {
            match ops[op_idx] {
                DiffOp::Equal(_) => {
                    old_line += 1;
                    new_line += 1;
                }
                DiffOp::Delete(_) => {
                    old_line += 1;
                }
                DiffOp::Insert(_) => {
                    new_line += 1;
                }
            }
            op_idx += 1;
        }

        let hunk_old_start = old_line;
        let hunk_new_start = new_line;
        let mut hunk_old_count = 0usize;
        let mut hunk_new_count = 0usize;
        let mut hunk_body = String::new();

        while op_idx < c_end {
            match ops[op_idx] {
                DiffOp::Equal(line) => {
                    hunk_body.push(' ');
                    hunk_body.push_str(line);
                    hunk_body.push('\n');
                    hunk_old_count += 1;
                    hunk_new_count += 1;
                    old_line += 1;
                    new_line += 1;
                }
                DiffOp::Delete(line) => {
                    hunk_body.push('-');
                    hunk_body.push_str(line);
                    hunk_body.push('\n');
                    hunk_old_count += 1;
                    old_line += 1;
                }
                DiffOp::Insert(line) => {
                    hunk_body.push('+');
                    hunk_body.push_str(line);
                    hunk_body.push('\n');
                    hunk_new_count += 1;
                    new_line += 1;
                }
            }
            op_idx += 1;
        }

        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            hunk_old_start, hunk_old_count, hunk_new_start, hunk_new_count
        ));
        out.push_str(&hunk_body);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_diff_added() {
        let diff = generate_unified_diff("src/new.rs", None, Some("fn main() {\n    println!(\"hello\");\n}\n"));
        assert!(diff.starts_with("--- /dev/null\n+++ b/src/new.rs\n@@ -0,0 +1,3 @@\n"));
        assert!(diff.contains("+fn main() {"));
        assert!(diff.contains("+    println!(\"hello\");"));
    }

    #[test]
    fn test_unified_diff_deleted() {
        let diff = generate_unified_diff("notes.txt", Some("note 1\nnote 2\n"), None);
        assert!(diff.starts_with("--- a/notes.txt\n+++ /dev/null\n@@ -1,2 +0,0 @@\n"));
        assert!(diff.contains("-note 1"));
        assert!(diff.contains("-note 2"));
    }

    #[test]
    fn test_unified_diff_modified() {
        let old = "line 1\nline 2\nline 3\n";
        let new = "line 1\nline 2 modified\nline 3\n";
        let diff = generate_unified_diff("file.txt", Some(old), Some(new));
        assert!(diff.contains("--- a/file.txt"));
        assert!(diff.contains("+++ b/file.txt"));
        assert!(diff.contains("@@ -1,3 +1,3 @@"));
        assert!(diff.contains(" line 1"));
        assert!(diff.contains("-line 2"));
        assert!(diff.contains("+line 2 modified"));
        assert!(diff.contains(" line 3"));
    }

    #[test]
    fn test_unified_diff_identical() {
        let content = "same line\nanother line\n";
        let diff = generate_unified_diff("same.txt", Some(content), Some(content));
        assert!(diff.is_empty());
    }
}

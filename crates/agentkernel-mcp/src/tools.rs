//! MCP Tools Registry, Schema Definitions and Path Security.

use crate::protocol::Tool;
use serde_json::json;
use std::path::{Component, Path, PathBuf};

/// Returns the specification of all 7 MCP tools exposed by AgentKernel.
pub fn mcp_tools_list() -> Vec<Tool> {
    vec![
        Tool {
            name: "sandbox_acquire".to_string(),
            description: "Acquire an isolated micro-sandbox from the pre-warmed pool for execution.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "workspace_path": {
                        "type": "string",
                        "description": "Host filesystem directory to mount into the sandbox"
                    },
                    "base_rootfs": {
                        "type": "string",
                        "description": "Optional custom base rootfs image or template path"
                    },
                    "env_vars": {
                        "type": "object",
                        "additionalProperties": { "type": "string" },
                        "description": "Environment variables key-value mapping"
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Sandbox maximum lease lifetime in seconds (default: 300)"
                    }
                },
                "required": ["workspace_path"]
            }),
        },
        Tool {
            name: "sandbox_exec".to_string(),
            description: "Execute a command inside the leased micro-sandbox isolate.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the leased sandbox"
                    },
                    "cmd": {
                        "type": "string",
                        "description": "Command binary or script to execute"
                    },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command line arguments list"
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Command execution timeout in milliseconds (default: 30000)"
                    }
                },
                "required": ["session_id", "cmd"]
            }),
        },
        Tool {
            name: "sandbox_read_file".to_string(),
            description: "Read a file from within the sandbox workspace safely.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the leased sandbox"
                    },
                    "path": {
                        "type": "string",
                        "description": "Relative file path inside the workspace"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Optional 1-indexed starting line number"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Optional maximum number of lines to read"
                    }
                },
                "required": ["session_id", "path"]
            }),
        },
        Tool {
            name: "sandbox_write_patch".to_string(),
            description: "Write or patch a file safely within the sandbox workspace.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the leased sandbox"
                    },
                    "path": {
                        "type": "string",
                        "description": "Relative file path inside the workspace"
                    },
                    "content": {
                        "type": "string",
                        "description": "File content to write or patch"
                    },
                    "append": {
                        "type": "boolean",
                        "description": "If true, append to existing file; otherwise overwrite (default: false)"
                    }
                },
                "required": ["session_id", "path", "content"]
            }),
        },
        Tool {
            name: "sandbox_create_checkpoint".to_string(),
            description: "Create an instant CoW snapshot/checkpoint of current sandbox filesystem state.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the leased sandbox"
                    },
                    "name": {
                        "type": "string",
                        "description": "Descriptive name or label for the checkpoint"
                    }
                },
                "required": ["session_id", "name"]
            }),
        },
        Tool {
            name: "sandbox_rollback".to_string(),
            description: "Rollback sandbox filesystem state to a previously saved checkpoint.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the leased sandbox"
                    },
                    "checkpoint_id": {
                        "type": "string",
                        "description": "Identifier of the checkpoint to rollback to"
                    }
                },
                "required": ["session_id", "checkpoint_id"]
            }),
        },
        Tool {
            name: "sandbox_release".to_string(),
            description: "Release and terminate the sandbox isolate, returning resources to the pool.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the sandbox to release"
                    }
                },
                "required": ["session_id"]
            }),
        },
        Tool {
            name: "sandbox_diff".to_string(),
            description: "Inspect modified files and unified diff between checkpoints or current workspace.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the leased sandbox"
                    },
                    "from_checkpoint": {
                        "type": "string",
                        "description": "Optional base checkpoint ID to compare from"
                    },
                    "to_checkpoint": {
                        "type": "string",
                        "description": "Optional target checkpoint ID to compare to (defaults to current workspace)"
                    }
                },
                "required": ["session_id"]
            }),
        },
        Tool {
            name: "sandbox_list_checkpoints".to_string(),
            description: "List all checkpoints/snapshots for a sandbox session with metadata and size in bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the leased sandbox"
                    }
                },
                "required": ["session_id"]
            }),
        },
        Tool {
            name: "sandbox_metrics".to_string(),
            description: "Retrieve current sandbox isolate resource and performance metrics.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Session ID of the leased sandbox"
                    }
                },
                "required": ["session_id"]
            }),
        },
    ]
}

/// Safely resolves a path relative to the workspace, strictly preventing path traversal attacks.
pub fn resolve_safe_path(workspace: &Path, rel_path: &str) -> Result<PathBuf, String> {
    let raw = Path::new(rel_path);

    // Reject absolute paths
    if raw.is_absolute() {
        return Err(format!("Absolute path '{rel_path}' is not permitted; path must be workspace-relative"));
    }

    // Reject parent dir traversal components (..)
    for component in raw.components() {
        match component {
            Component::ParentDir => {
                return Err(format!("Directory traversal ('..') detected in '{rel_path}': access denied"));
            }
            Component::Prefix(_) => {
                return Err(format!("Windows drive prefix detected in '{rel_path}': access denied"));
            }
            Component::RootDir => {
                return Err(format!("Root directory detected in '{rel_path}': access denied"));
            }
            Component::Normal(_) | Component::CurDir => {}
        }
    }

    let joined = workspace.join(raw);
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tools_list_completeness() {
        let tools = mcp_tools_list();
        assert_eq!(tools.len(), 10);
        let names: Vec<String> = tools.into_iter().map(|t| t.name).collect();
        assert!(names.contains(&"sandbox_acquire".to_string()));
        assert!(names.contains(&"sandbox_exec".to_string()));
        assert!(names.contains(&"sandbox_read_file".to_string()));
        assert!(names.contains(&"sandbox_write_patch".to_string()));
        assert!(names.contains(&"sandbox_create_checkpoint".to_string()));
        assert!(names.contains(&"sandbox_rollback".to_string()));
        assert!(names.contains(&"sandbox_release".to_string()));
        assert!(names.contains(&"sandbox_diff".to_string()));
        assert!(names.contains(&"sandbox_list_checkpoints".to_string()));
        assert!(names.contains(&"sandbox_metrics".to_string()));
    }

    #[test]
    fn test_resolve_safe_path() {
        let base = Path::new("/tmp/workspace");
        assert!(resolve_safe_path(base, "src/main.rs").is_ok());
        assert!(resolve_safe_path(base, "sub/dir/file.txt").is_ok());
        assert!(resolve_safe_path(base, "../secret.txt").is_err());
        assert!(resolve_safe_path(base, "src/../../secret.txt").is_err());
        assert!(resolve_safe_path(base, "/etc/passwd").is_err());
    }
}

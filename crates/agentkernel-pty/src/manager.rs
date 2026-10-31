use crate::token_guard::TokenGuard;
use crate::{CommandOutput, PtyError, PtyRunner};
use async_trait::async_trait;
use std::process::Stdio;
use std::time::Instant;
use tokio::io::AsyncBufReadExt;

/// PtyManager orchestrates asynchronous command execution inside pseudo-terminals
/// or isolated process sessions with LLM Token Guard ring-buffer protection.
#[derive(Debug, Clone)]
pub struct PtyManager {
    default_timeout_ms: u64,
    default_max_lines: usize,
    max_bytes: usize,
}

impl Default for PtyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PtyManager {
    /// Creates a new PtyManager with default limits (30s timeout, 1000 lines, 10MB).
    pub fn new() -> Self {
        Self {
            default_timeout_ms: 30_000,
            default_max_lines: 1_000,
            max_bytes: 10 * 1024 * 1024,
        }
    }

    /// Sets default execution timeout in milliseconds.
    pub fn with_default_timeout(mut self, timeout_ms: u64) -> Self {
        self.default_timeout_ms = timeout_ms;
        self
    }

    /// Sets default maximum lines before Token Guard truncation.
    pub fn with_default_max_lines(mut self, max_lines: usize) -> Self {
        self.default_max_lines = max_lines;
        self
    }

    /// Sets maximum bytes allowed for stdout/stderr buffers.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Linux PTY allocation helper when running on Linux hosts.
    #[cfg(target_os = "linux")]
    pub fn allocate_pty(&self) -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), PtyError> {
        nix::pty::openpty(None, None)
            .map(|res| (res.master, res.slave))
            .map_err(|e| PtyError::Allocation(e.to_string()))
    }

    /// Spawns an interactive bidirectional session with streaming broadcast and signal support.
    pub fn spawn_interactive(
        &self,
        cmd: &str,
        args: &[String],
        working_dir: &str,
    ) -> Result<crate::session::InteractiveSession, PtyError> {
        crate::session::InteractiveSession::spawn(
            cmd,
            args,
            working_dir,
            self.default_max_lines,
            self.max_bytes,
        )
    }
}

#[async_trait]
impl PtyRunner for PtyManager {
    async fn run_command(
        &self,
        cmd: &str,
        args: &[String],
        working_dir: &str,
        timeout_ms: u64,
        max_lines: usize,
    ) -> Result<CommandOutput, PtyError> {
        let timeout_ms = if timeout_ms == 0 {
            self.default_timeout_ms
        } else {
            timeout_ms
        };

        let max_lines = if max_lines == 0 {
            self.default_max_lines
        } else {
            max_lines
        };

        let start = Instant::now();
        let timeout_dur = std::time::Duration::from_millis(timeout_ms);

        let mut command = build_command(cmd, args, working_dir);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdin(Stdio::null());

        let mut child = command.spawn().map_err(PtyError::Io)?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let max_bytes = self.max_bytes;

        // Concurrent asynchronous reader for stdout
        let stdout_task = tokio::spawn(async move {
            let mut guard = TokenGuard::new(max_lines)
                .with_max_bytes(max_bytes)
                .create_buffer();
            if let Some(stdout) = stdout {
                let reader = tokio::io::BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    guard.push_line(line);
                }
            }
            guard.finish()
        });

        // Concurrent asynchronous reader for stderr
        let stderr_task = tokio::spawn(async move {
            let mut guard = TokenGuard::new(max_lines)
                .with_max_bytes(max_bytes)
                .create_buffer();
            if let Some(stderr) = stderr {
                let reader = tokio::io::BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    guard.push_line(line);
                }
            }
            guard.finish()
        });

        // Await child process termination with strict timeout
        let status_res = tokio::time::timeout(timeout_dur, child.wait()).await;

        let status = match status_res {
            Ok(Ok(status)) => status,
            Ok(Err(io_err)) => {
                stdout_task.abort();
                stderr_task.abort();
                return Err(PtyError::Io(io_err));
            }
            Err(_) => {
                // Timeout fired! Immediately kill the child process and reap zombie
                let _ = child.kill().await;
                let _ = child.wait().await;
                stdout_task.abort();
                stderr_task.abort();
                return Err(PtyError::Timeout);
            }
        };

        let stdout_res = stdout_task
            .await
            .map_err(|e| PtyError::Allocation(format!("Stdout reader join failed: {}", e)))?;
        let stderr_res = stderr_task
            .await
            .map_err(|e| PtyError::Allocation(format!("Stderr reader join failed: {}", e)))?;

        let duration_ms = start.elapsed().as_millis() as u64;
        let exit_code = status.code().unwrap_or(-1);
        let truncated = stdout_res.truncated || stderr_res.truncated;
        let total_lines = stdout_res.total_lines + stderr_res.total_lines;

        Ok(CommandOutput {
            exit_code,
            stdout: stdout_res.content,
            stderr: stderr_res.content,
            duration_ms,
            truncated,
            total_lines,
        })
    }
}

/// Helper function to build cross-platform commands.
pub(crate) fn build_command(cmd: &str, args: &[String], working_dir: &str) -> tokio::process::Command {
    let mut command = if cfg!(target_os = "windows") {
        if cmd == "echo" || cmd == "dir" || cmd == "type" || cmd == "cd" {
            let mut c = tokio::process::Command::new("cmd");
            c.arg("/C").arg(cmd).args(args);
            c
        } else {
            let mut c = tokio::process::Command::new(cmd);
            c.args(args);
            c
        }
    } else {
        let mut c = tokio::process::Command::new(cmd);
        c.args(args);
        c
    };

    if !working_dir.is_empty() && working_dir != "." {
        command.current_dir(working_dir);
    }

    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pty_manager_echo() {
        let manager = PtyManager::new();
        let (cmd, args) = if cfg!(target_os = "windows") {
            ("cmd", vec!["/C".into(), "echo Hello AgentKernel".into()])
        } else {
            ("echo", vec!["Hello AgentKernel".into()])
        };

        let output = manager
            .run_command(cmd, &args, ".", 5000, 100)
            .await
            .expect("Command execution should succeed");

        assert_eq!(output.exit_code, 0);
        assert!(output.stdout.contains("Hello AgentKernel"));
        assert!(!output.truncated);
        assert!(output.total_lines >= 1);
    }

    #[tokio::test]
    async fn test_pty_manager_timeout() {
        let manager = PtyManager::new();
        let (cmd, args) = if cfg!(target_os = "windows") {
            (
                "powershell",
                vec!["-Command".into(), "Start-Sleep -Milliseconds 2000".into()],
            )
        } else {
            ("sleep", vec!["2".into()])
        };

        // Set a small 100ms timeout
        let result = manager.run_command(cmd, &args, ".", 100, 100).await;

        match result {
            Err(PtyError::Timeout) => {
                // Expected timeout error
            }
            other => panic!("Expected PtyError::Timeout, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_pty_manager_truncation() {
        let manager = PtyManager::new();
        let (cmd, args) = if cfg!(target_os = "windows") {
            (
                "powershell",
                vec![
                    "-Command".into(),
                    "1..50 | ForEach-Object { Write-Output \"line $_\" }".into(),
                ],
            )
        } else {
            (
                "sh",
                vec![
                    "-c".into(),
                    "for i in $(seq 1 50); do echo \"line $i\"; done".into(),
                ],
            )
        };

        // Request max 10 lines
        let output = manager
            .run_command(cmd, &args, ".", 10000, 10)
            .await
            .expect("Command execution should succeed");

        assert_eq!(output.exit_code, 0);
        assert!(output.truncated, "Output should be marked truncated");
        assert_eq!(output.total_lines, 50, "Total lines should be 50");
        assert!(
            output.stdout.contains("[... 40 lines truncated ...]"),
            "Stdout should contain truncation marker, actual: {}",
            output.stdout
        );
        assert!(output.stdout.starts_with("line 1"));
        assert!(output.stdout.ends_with("line 50"));
    }
}

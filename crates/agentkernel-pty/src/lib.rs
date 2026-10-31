//! AgentKernel PTY: Pseudo-terminal multiplexer and LLM Token Guard.

pub mod ansi;
pub mod manager;
pub mod session;
pub mod token_guard;

pub use ansi::strip_ansi;
pub use manager::PtyManager;
pub use session::{InteractiveSession, PtyOutputChunk, PtyStreamer};
pub use token_guard::{TokenGuard, TokenGuardRingBuffer, TruncateResult};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PtyError {
    #[error("PTY allocation failed: {0}")]
    Allocation(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Execution timed out")]
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub truncated: bool,
    pub total_lines: usize,
}

#[async_trait]
pub trait PtyRunner: Send + Sync {
    async fn run_command(
        &self,
        cmd: &str,
        args: &[String],
        working_dir: &str,
        timeout_ms: u64,
        max_lines: usize,
    ) -> Result<CommandOutput, PtyError>;
}

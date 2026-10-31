//! AgentKernel Core: Sandbox Orchestrator, Warm Pool Manager & State Machine.

pub mod pool;
pub mod sandbox;

pub use pool::{PoolConfig, PoolManager, WarmPool};
pub use sandbox::{DefaultSandboxSession, LeasedSandboxSession, SandboxConfig, SandboxSession};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Sandbox runtime error: {0}")]
    Runtime(#[from] agentkernel_runtime::RuntimeError),
    #[error("Storage engine error: {0}")]
    Storage(#[from] agentkernel_fs::FsError),
    #[error("PTY error: {0}")]
    Pty(#[from] agentkernel_pty::PtyError),
    #[error("Network error: {0}")]
    Net(#[from] agentkernel_net::NetError),
    #[error("Sandbox {0} not found")]
    NotFound(String),
    #[error("Pool exhausted")]
    PoolExhausted,
    #[error("Invalid session state: {0}")]
    InvalidState(String),
    #[error("Execution timed out")]
    Timeout,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxStatus {
    Creating,
    Warm,
    Leased,
    Executing,
    Terminating,
}

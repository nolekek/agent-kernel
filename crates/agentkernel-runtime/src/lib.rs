//! AgentKernel Runtime: Low-level process isolation primitives.
//!
//! Provides Linux namespaces, cgroups v2 resource accounting,
//! seccomp-bpf system call filters, and portable cross-platform fallbacks.

pub mod cgroup;
pub mod driver;
pub mod namespace;
pub mod seccomp;

pub use cgroup::CgroupController;
pub use driver::{NativeRuntimeDriver, PortableRuntimeDriver};
#[cfg(target_os = "linux")]
pub use driver::LinuxRuntimeDriver;
pub use namespace::NamespaceConfig;
pub use seccomp::{SeccompAction, SeccompFilter};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("System call failed: {0}")]
    Syscall(String),
    #[error("Resource limit error: {0}")]
    ResourceLimit(String),
    #[error("Platform unsupported: {0}")]
    UnsupportedPlatform(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Namespace error: {0}")]
    Namespace(String),
    #[error("Cgroup error: {0}")]
    Cgroup(String),
    #[error("Seccomp error: {0}")]
    Seccomp(String),
    #[error("Process {0} not found")]
    ProcessNotFound(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_bytes: u64,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub max_pids: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 1024 * 1024 * 1024, // 1 GB
            cpu_quota_us: 100_000,
            cpu_period_us: 100_000,
            max_pids: 256,
        }
    }
}

impl ResourceLimits {
    pub fn unlimited() -> Self {
        Self {
            max_memory_bytes: 0,
            cpu_quota_us: 0,
            cpu_period_us: 100_000,
            max_pids: 0,
        }
    }

    pub fn with_memory(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    pub fn with_cpu(mut self, quota_us: u64, period_us: u64) -> Self {
        self.cpu_quota_us = quota_us;
        self.cpu_period_us = period_us;
        self
    }

    pub fn with_pids(mut self, pids: u32) -> Self {
        self.max_pids = pids;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub executable: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: String,
    pub rootfs_path: String,
    pub limits: ResourceLimits,
}

impl ProcessConfig {
    pub fn new<S: Into<String>>(executable: S) -> Self {
        Self {
            executable: executable.into(),
            args: Vec::new(),
            env: Vec::new(),
            working_dir: String::new(),
            rootfs_path: String::new(),
            limits: ResourceLimits::default(),
        }
    }

    pub fn arg<S: Into<String>>(mut self, arg: S) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env<K: Into<String>, V: Into<String>>(mut self, key: K, val: V) -> Self {
        self.env.push((key.into(), val.into()));
        self
    }

    pub fn working_dir<S: Into<String>>(mut self, dir: S) -> Self {
        self.working_dir = dir.into();
        self
    }

    pub fn rootfs_path<S: Into<String>>(mut self, path: S) -> Self {
        self.rootfs_path = path.into();
        self
    }

    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }
}

#[async_trait]
pub trait RuntimeDriver: Send + Sync {
    async fn spawn_isolated(&self, config: &ProcessConfig) -> Result<u32, RuntimeError>;
    async fn kill_isolated(&self, pid: u32) -> Result<(), RuntimeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_memory_bytes, 1024 * 1024 * 1024);
        assert_eq!(limits.cpu_quota_us, 100_000);
        assert_eq!(limits.cpu_period_us, 100_000);
        assert_eq!(limits.max_pids, 256);
    }

    #[test]
    fn test_resource_limits_builder() {
        let limits = ResourceLimits::unlimited()
            .with_memory(2 * 1024 * 1024 * 1024)
            .with_cpu(50_000, 100_000)
            .with_pids(512);

        assert_eq!(limits.max_memory_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.cpu_quota_us, 50_000);
        assert_eq!(limits.cpu_period_us, 100_000);
        assert_eq!(limits.max_pids, 512);
    }

    #[test]
    fn test_resource_limits_serde() {
        let limits = ResourceLimits::default();
        let json = serde_json::to_string(&limits).expect("serialize limits");
        let deserialized: ResourceLimits = serde_json::from_str(&json).expect("deserialize limits");
        assert_eq!(limits, deserialized);
    }

    #[test]
    fn test_process_config_builder() {
        let config = ProcessConfig::new("echo")
            .arg("hello")
            .arg("world")
            .env("AGENT_ID", "agent-007")
            .working_dir("/tmp/sandbox")
            .rootfs_path("/var/lib/rootfs")
            .limits(ResourceLimits::default().with_memory(512 * 1024 * 1024));

        assert_eq!(config.executable, "echo");
        assert_eq!(config.args, vec!["hello".to_string(), "world".to_string()]);
        assert_eq!(
            config.env,
            vec![("AGENT_ID".to_string(), "agent-007".to_string())]
        );
        assert_eq!(config.working_dir, "/tmp/sandbox");
        assert_eq!(config.rootfs_path, "/var/lib/rootfs");
        assert_eq!(config.limits.max_memory_bytes, 512 * 1024 * 1024);
    }

    #[test]
    fn test_process_config_serde() {
        let config = ProcessConfig::new("python3")
            .args(["-c", "print('test')"])
            .env("PYTHONDONTWRITEBYTECODE", "1");

        let json = serde_json::to_string(&config).expect("serialize config");
        let decoded: ProcessConfig = serde_json::from_str(&json).expect("deserialize config");
        assert_eq!(decoded.executable, "python3");
        assert_eq!(decoded.args, vec!["-c", "print('test')"]);
    }

    #[tokio::test]
    async fn test_portable_driver_lifecycle() {
        let driver = PortableRuntimeDriver::new();

        #[cfg(target_os = "windows")]
        let cfg = ProcessConfig::new("cmd")
            .args(["/C", "timeout", "/t", "10", "/nobreak"]);

        #[cfg(not(target_os = "windows"))]
        let cfg = ProcessConfig::new("sleep").arg("10");

        let pid_res = driver.spawn_isolated(&cfg).await;
        assert!(pid_res.is_ok(), "Process spawn should succeed: {:?}", pid_res);
        let pid = pid_res.unwrap();
        assert!(pid > 0);

        // Kill process
        let kill_res = driver.kill_isolated(pid).await;
        assert!(kill_res.is_ok());
    }
}

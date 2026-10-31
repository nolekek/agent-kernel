//! Runtime Drivers for Isolated Process Execution.

use crate::cgroup::CgroupController;
#[cfg(target_os = "linux")]
use crate::namespace::NamespaceConfig;
#[cfg(target_os = "linux")]
use crate::seccomp::SeccompFilter;
use crate::{ProcessConfig, RuntimeDriver, RuntimeError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::info;

/// Portable runtime driver with environment & working directory isolation.
pub struct PortableRuntimeDriver {
    active_processes: Arc<Mutex<HashMap<u32, Child>>>,
    cgroup_controller: CgroupController,
}

impl Default for PortableRuntimeDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl PortableRuntimeDriver {
    pub fn new() -> Self {
        Self {
            active_processes: Arc::new(Mutex::new(HashMap::new())),
            cgroup_controller: CgroupController::default(),
        }
    }
}

#[async_trait]
impl RuntimeDriver for PortableRuntimeDriver {
    async fn spawn_isolated(&self, config: &ProcessConfig) -> Result<u32, RuntimeError> {
        // Ensure working directory exists if specified
        if !config.working_dir.is_empty() {
            let p = Path::new(&config.working_dir);
            if !p.exists() {
                tokio::fs::create_dir_all(p).await.map_err(|e| {
                    RuntimeError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Failed to create working_dir {:?}: {}", p, e),
                    ))
                })?;
            }
        }

        let mut cmd = Command::new(&config.executable);
        cmd.args(&config.args);

        if !config.working_dir.is_empty() {
            cmd.current_dir(&config.working_dir);
        }

        // Environment isolation: clear host env and inject minimal system env vars + explicit config.env
        cmd.env_clear();

        #[cfg(target_os = "windows")]
        {
            // Essential Windows system variables needed to resolve dynamic libraries and run basic commands
            const PRESERVED_WIN_VARS: &[&str] = &[
                "SYSTEMROOT",
                "SYSTEMDRIVE",
                "PATH",
                "PATHEXT",
                "TEMP",
                "TMP",
                "COMSPEC",
                "WINDIR",
            ];
            for &var in PRESERVED_WIN_VARS {
                if let Ok(val) = std::env::var(var) {
                    cmd.env(var, val);
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            const PRESERVED_UNIX_VARS: &[&str] = &["PATH", "HOME", "USER", "TMPDIR"];
            for &var in PRESERVED_UNIX_VARS {
                if let Ok(val) = std::env::var(var) {
                    cmd.env(var, val);
                }
            }
        }

        // Apply sandbox-configured environment variables
        for (k, v) in &config.env {
            cmd.env(k, v);
        }

        // Spawn child process
        let child = cmd.spawn().map_err(|e| {
            RuntimeError::Syscall(format!(
                "Failed to spawn isolated process '{}': {}",
                config.executable, e
            ))
        })?;

        let pid = child.id().ok_or_else(|| {
            RuntimeError::Syscall("Failed to retrieve child process PID".to_string())
        })?;

        // Apply resource limits mock accounting
        let cgroup_name = format!("proc_{}", pid);
        let _ = self.cgroup_controller.create_cgroup(&cgroup_name, &config.limits);
        let _ = self.cgroup_controller.attach_process(&cgroup_name, pid);

        self.active_processes.lock().await.insert(pid, child);
        info!(pid = pid, executable = %config.executable, "Isolated process spawned");
        Ok(pid)
    }

    async fn kill_isolated(&self, pid: u32) -> Result<(), RuntimeError> {
        let mut processes = self.active_processes.lock().await;

        if let Some(mut child) = processes.remove(&pid) {
            let _ = child.start_kill();
        } else {
            // Process not in map, attempt platform-level kill
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output();
            }
            #[cfg(target_os = "linux")]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
            }
        }

        // Clean up cgroup
        let cgroup_name = format!("proc_{}", pid);
        let _ = self.cgroup_controller.remove_cgroup(&cgroup_name);

        info!(pid = pid, "Isolated process killed and cleaned up");
        Ok(())
    }
}

/// Linux-native runtime driver utilizing namespaces, cgroups v2, and seccomp-bpf.
#[cfg(target_os = "linux")]
pub struct LinuxRuntimeDriver {
    active_processes: Arc<Mutex<HashMap<u32, (Child, String)>>>,
    cgroup_controller: CgroupController,
    namespace_config: NamespaceConfig,
    seccomp_filter: SeccompFilter,
}

#[cfg(target_os = "linux")]
impl Default for LinuxRuntimeDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl LinuxRuntimeDriver {
    pub fn new() -> Self {
        Self {
            active_processes: Arc::new(Mutex::new(HashMap::new())),
            cgroup_controller: CgroupController::default(),
            namespace_config: NamespaceConfig::default(),
            seccomp_filter: SeccompFilter::default(),
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl RuntimeDriver for LinuxRuntimeDriver {
    async fn spawn_isolated(&self, config: &ProcessConfig) -> Result<u32, RuntimeError> {
        let cgroup_id = format!("agentkernel_{}", uuid_simple());
        let _ = self.cgroup_controller.create_cgroup(&cgroup_id, &config.limits);

        let ns = self.namespace_config.clone();
        let seccomp = self.seccomp_filter.clone();
        let rootfs = config.rootfs_path.clone();

        let mut cmd = Command::new(&config.executable);
        cmd.args(&config.args);

        if !config.working_dir.is_empty() {
            cmd.current_dir(&config.working_dir);
        }

        cmd.env_clear();
        for (k, v) in &config.env {
            cmd.env(k, v);
        }

        // Linux pre_exec hook: setup namespaces and seccomp filter in child before exec
        unsafe {
            cmd.pre_exec(move || {
                // Apply namespaces
                if let Err(e) = ns.apply() {
                    eprintln!("Namespace setup error in child: {}", e);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                }

                // If rootfs specified, chroot
                if !rootfs.is_empty() {
                    if let Err(e) = ns.setup_rootfs(Path::new(&rootfs)) {
                        eprintln!("Rootfs setup error in child: {}", e);
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                    }
                }

                // Apply seccomp filter
                if let Err(e) = seccomp.apply() {
                    eprintln!("Seccomp filter error in child: {}", e);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
                }

                Ok(())
            });
        }

        let child = cmd.spawn().map_err(|e| {
            RuntimeError::Syscall(format!("Failed to spawn Linux isolated process: {}", e))
        })?;

        let pid = child.id().ok_or_else(|| {
            RuntimeError::Syscall("Failed to retrieve child process PID".to_string())
        })?;

        // Attach PID to cgroup in parent
        let _ = self.cgroup_controller.attach_process(&cgroup_id, pid);

        self.active_processes
            .lock()
            .await
            .insert(pid, (child, cgroup_id));

        info!(pid = pid, "Linux isolated process started in sandbox");
        Ok(pid)
    }

    async fn kill_isolated(&self, pid: u32) -> Result<(), RuntimeError> {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;

        let mut procs = self.active_processes.lock().await;
        if let Some((mut child, cgroup_id)) = procs.remove(&pid) {
            let _ = child.start_kill();
            let _ = self.cgroup_controller.remove_cgroup(&cgroup_id);
        } else {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }

        info!(pid = pid, "Killed isolated process");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", nanos)
}

/// Type alias for platform native runtime driver.
#[cfg(target_os = "linux")]
pub type NativeRuntimeDriver = LinuxRuntimeDriver;

#[cfg(not(target_os = "linux"))]
pub type NativeRuntimeDriver = PortableRuntimeDriver;

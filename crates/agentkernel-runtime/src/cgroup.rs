//! Cgroups v2 Resource Accounting & Limits Controller.

use crate::{ResourceLimits, RuntimeError};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct CgroupController {
    base_path: PathBuf,
}

impl Default for CgroupController {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        let base = PathBuf::from("/sys/fs/cgroup/agentkernel");
        #[cfg(not(target_os = "linux"))]
        let base = std::env::temp_dir().join("agentkernel_cgroups_mock");

        Self { base_path: base }
    }
}

impl CgroupController {
    pub fn new<P: Into<PathBuf>>(base_path: P) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Creates a cgroup v2 node for the given identifier.
    pub fn create_cgroup(&self, name: &str, limits: &ResourceLimits) -> Result<PathBuf, RuntimeError> {
        let cgroup_dir = self.base_path.join(name);
        fs::create_dir_all(&cgroup_dir).map_err(|e| {
            RuntimeError::Cgroup(format!("Failed to create cgroup directory {:?}: {}", cgroup_dir, e))
        })?;

        self.apply_limits(name, limits)?;
        info!(cgroup = %name, path = ?cgroup_dir, "Cgroup v2 initialized");
        Ok(cgroup_dir)
    }

    /// Applies resource limits (memory, cpu, pids) to a cgroup.
    pub fn apply_limits(&self, name: &str, limits: &ResourceLimits) -> Result<(), RuntimeError> {
        let cgroup_dir = self.base_path.join(name);
        if !cgroup_dir.exists() {
            return Err(RuntimeError::Cgroup(format!(
                "Cgroup directory {:?} does not exist",
                cgroup_dir
            )));
        }

        // Memory limit: memory.max
        let mem_file = cgroup_dir.join("memory.max");
        let mem_val = if limits.max_memory_bytes == 0 {
            "max".to_string()
        } else {
            limits.max_memory_bytes.to_string()
        };
        fs::write(&mem_file, mem_val.as_bytes()).map_err(|e| {
            RuntimeError::ResourceLimit(format!("Failed to write memory.max: {}", e))
        })?;

        // CPU limit: cpu.max ("quota period")
        let cpu_file = cgroup_dir.join("cpu.max");
        let cpu_val = if limits.cpu_quota_us == 0 {
            format!("max {}", limits.cpu_period_us)
        } else {
            format!("{} {}", limits.cpu_quota_us, limits.cpu_period_us)
        };
        fs::write(&cpu_file, cpu_val.as_bytes()).map_err(|e| {
            RuntimeError::ResourceLimit(format!("Failed to write cpu.max: {}", e))
        })?;

        // PIDs limit: pids.max
        let pids_file = cgroup_dir.join("pids.max");
        let pids_val = if limits.max_pids == 0 {
            "max".to_string()
        } else {
            limits.max_pids.to_string()
        };
        fs::write(&pids_file, pids_val.as_bytes()).map_err(|e| {
            RuntimeError::ResourceLimit(format!("Failed to write pids.max: {}", e))
        })?;

        debug!(cgroup = %name, ?limits, "Applied cgroups v2 limits");
        Ok(())
    }

    /// Attaches a process PID to the cgroup procs file.
    pub fn attach_process(&self, name: &str, pid: u32) -> Result<(), RuntimeError> {
        let procs_file = self.base_path.join(name).join("cgroup.procs");
        fs::write(&procs_file, pid.to_string().as_bytes()).map_err(|e| {
            RuntimeError::Cgroup(format!(
                "Failed to attach pid {} to cgroup {}: {}",
                pid, name, e
            ))
        })?;
        debug!(cgroup = %name, pid = pid, "Attached process to cgroup");
        Ok(())
    }

    /// Removes the cgroup directory.
    pub fn remove_cgroup(&self, name: &str) -> Result<(), RuntimeError> {
        let cgroup_dir = self.base_path.join(name);
        if cgroup_dir.exists() {
            fs::remove_dir(&cgroup_dir).or_else(|_| fs::remove_dir_all(&cgroup_dir)).map_err(|e| {
                RuntimeError::Cgroup(format!("Failed to remove cgroup directory {:?}: {}", cgroup_dir, e))
            })?;
            debug!(cgroup = %name, "Cgroup removed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_cgroup_create_apply_and_remove() {
        let tmp = tempdir().unwrap();
        let controller = CgroupController::new(tmp.path().join("cgroup_test"));

        let limits = ResourceLimits {
            max_memory_bytes: 512 * 1024 * 1024,
            cpu_quota_us: 50_000,
            cpu_period_us: 100_000,
            max_pids: 128,
        };

        let cgroup_path = controller.create_cgroup("test_cg_1", &limits).unwrap();
        assert!(cgroup_path.exists());

        // Check file contents
        let mem = fs::read_to_string(cgroup_path.join("memory.max")).unwrap();
        assert_eq!(mem, "536870912");

        let cpu = fs::read_to_string(cgroup_path.join("cpu.max")).unwrap();
        assert_eq!(cpu, "50000 100000");

        let pids = fs::read_to_string(cgroup_path.join("pids.max")).unwrap();
        assert_eq!(pids, "128");

        // Attach a mock pid
        controller.attach_process("test_cg_1", 12345).unwrap();
        let procs = fs::read_to_string(cgroup_path.join("cgroup.procs")).unwrap();
        assert_eq!(procs, "12345");

        // Clean up
        controller.remove_cgroup("test_cg_1").unwrap();
        assert!(!cgroup_path.exists());
    }
}

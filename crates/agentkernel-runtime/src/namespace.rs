//! Linux Namespaces Isolation primitives (PID, MNT, IPC, UTS, USER, NET).

use crate::RuntimeError;
use std::path::Path;
#[cfg(not(target_os = "linux"))]
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::info;

#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub new_pid: bool,
    pub new_mount: bool,
    pub new_ipc: bool,
    pub new_uts: bool,
    pub new_user: bool,
    pub new_net: bool,
    pub hostname: Option<String>,
    pub uid_mapping: Option<(u32, u32, u32)>, // (inside_uid, outside_uid, count)
    pub gid_mapping: Option<(u32, u32, u32)>, // (inside_gid, outside_gid, count)
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            new_pid: true,
            new_mount: true,
            new_ipc: true,
            new_uts: true,
            new_user: true,
            new_net: true,
            hostname: Some("agentkernel-sandbox".to_string()),
            uid_mapping: Some((0, 1000, 1)),
            gid_mapping: Some((0, 1000, 1)),
        }
    }
}

impl NamespaceConfig {
    pub fn minimal() -> Self {
        Self {
            new_pid: true,
            new_mount: true,
            new_ipc: false,
            new_uts: false,
            new_user: false,
            new_net: false,
            hostname: None,
            uid_mapping: None,
            gid_mapping: None,
        }
    }

    /// Unshares namespaces in the current process.
    pub fn apply(&self) -> Result<(), RuntimeError> {
        #[cfg(target_os = "linux")]
        {
            use nix::sched::{unshare, CloneFlags};

            let mut flags = CloneFlags::empty();
            if self.new_user {
                flags |= CloneFlags::CLONE_NEWUSER;
            }
            if self.new_pid {
                flags |= CloneFlags::CLONE_NEWPID;
            }
            if self.new_mount {
                flags |= CloneFlags::CLONE_NEWNS;
            }
            if self.new_ipc {
                flags |= CloneFlags::CLONE_NEWIPC;
            }
            if self.new_uts {
                flags |= CloneFlags::CLONE_NEWUTS;
            }
            if self.new_net {
                flags |= CloneFlags::CLONE_NEWNET;
            }

            if !flags.is_empty() {
                unshare(flags).map_err(|e| {
                    RuntimeError::Namespace(format!("Failed to unshare namespaces ({:?}): {}", flags, e))
                })?;
            }

            // User mapping
            if self.new_user {
                self.setup_user_mappings()?;
            }

            // UTS hostname
            if self.new_uts {
                if let Some(ref host) = self.hostname {
                    nix::unistd::sethostname(host).map_err(|e| {
                        RuntimeError::Namespace(format!("Failed to set sandbox hostname: {}", e))
                    })?;
                }
            }

            info!("Configured Linux namespaces successfully");
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!(?self, "Namespace configuration recorded (noop on non-linux)");
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn setup_user_mappings(&self) -> Result<(), RuntimeError> {
        use std::fs;

        // Writing "deny" to setgroups is required before writing gid_map for unprivileged user namespaces
        let _ = fs::write("/proc/self/setgroups", "deny");

        if let Some((in_uid, out_uid, count)) = self.uid_mapping {
            let map_str = format!("{} {} {}\n", in_uid, out_uid, count);
            fs::write("/proc/self/uid_map", map_str.as_bytes()).map_err(|e| {
                RuntimeError::Namespace(format!("Failed to write uid_map: {}", e))
            })?;
        }

        if let Some((in_gid, out_gid, count)) = self.gid_mapping {
            let map_str = format!("{} {} {}\n", in_gid, out_gid, count);
            fs::write("/proc/self/gid_map", map_str.as_bytes()).map_err(|e| {
                RuntimeError::Namespace(format!("Failed to write gid_map: {}", e))
            })?;
        }

        Ok(())
    }

    /// Mounts new rootfs if specified and pivot_root or chroot.
    pub fn setup_rootfs(&self, rootfs_path: &Path) -> Result<(), RuntimeError> {
        if !rootfs_path.exists() {
            return Err(RuntimeError::Namespace(format!(
                "Rootfs path does not exist: {:?}",
                rootfs_path
            )));
        }

        #[cfg(target_os = "linux")]
        {
            use nix::mount::{mount, MsFlags};
            // Bind mount new rootfs to itself to allow pivot_root or chroot
            mount(
                Some(rootfs_path),
                rootfs_path,
                Option::<&str>::None,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                Option::<&str>::None,
            )
            .map_err(|e| RuntimeError::Syscall(format!("Failed to bind mount rootfs: {}", e)))?;

            nix::unistd::chroot(rootfs_path)
                .map_err(|e| RuntimeError::Syscall(format!("Failed to chroot: {}", e)))?;
            nix::unistd::chdir("/")
                .map_err(|e| RuntimeError::Syscall(format!("Failed to chdir to root: {}", e)))?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!(?rootfs_path, "Rootfs setup simulated (noop on non-linux)");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_config_defaults() {
        let cfg = NamespaceConfig::default();
        assert!(cfg.new_pid);
        assert!(cfg.new_mount);
        assert!(cfg.new_ipc);
        assert!(cfg.new_uts);
        assert!(cfg.new_user);
        assert_eq!(cfg.hostname.as_deref(), Some("agentkernel-sandbox"));
        assert!(cfg.apply().is_ok());
    }

    #[test]
    fn test_namespace_config_minimal() {
        let cfg = NamespaceConfig::minimal();
        assert!(cfg.new_pid);
        assert!(cfg.new_mount);
        assert!(!cfg.new_ipc);
        assert!(!cfg.new_uts);
        assert!(!cfg.new_user);
        assert!(cfg.apply().is_ok());
    }
}

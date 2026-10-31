//! Seccomp-BPF System Call Filtering.

use crate::RuntimeError;
#[cfg(not(target_os = "linux"))]
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::info;

// BPF opcodes and constants
pub const BPF_LD: u16 = 0x00;
pub const BPF_W: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_K: u16 = 0x00;
pub const BPF_RET: u16 = 0x06;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

pub const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
pub const AUDIT_ARCH_AARCH64: u32 = 0xc00000b7;

pub const EPERM: u32 = 1;

/// Raw BPF instruction struct matching `struct sock_filter`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// BPF program struct matching `struct sock_fprog`.
#[repr(C)]
#[derive(Debug)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

/// Syscall filter action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    Allow,
    Errno(u16),
    KillProcess,
}

impl SeccompAction {
    pub fn to_ret_code(self) -> u32 {
        match self {
            SeccompAction::Allow => SECCOMP_RET_ALLOW,
            SeccompAction::Errno(err) => SECCOMP_RET_ERRNO | (err as u32 & 0x0000ffff),
            SeccompAction::KillProcess => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

/// Seccomp BPF filter builder and compiler.
#[derive(Debug, Clone)]
pub struct SeccompFilter {
    pub default_action: SeccompAction,
    pub denied_syscalls: Vec<u32>,
}

impl Default for SeccompFilter {
    fn default() -> Self {
        // Default set of dangerous syscall numbers on x86_64 Linux:
        // 101: ptrace, 169: reboot, 246: kexec_load, 320: kexec_file_load
        // 161: chroot (optional restriction), 165: mount, 166: umount2
        // 167: swapon, 168: swapoff, 175: init_module, 176: delete_module, 313: finit_module
        // 321: bpf, 227: clock_settime
        let denied = vec![
            101, // ptrace
            165, // mount
            166, // umount2
            167, // swapon
            168, // swapoff
            169, // reboot
            175, // init_module
            176, // delete_module
            227, // clock_settime
            246, // kexec_load
            313, // finit_module
            320, // kexec_file_load
            321, // bpf
        ];

        Self {
            default_action: SeccompAction::Allow,
            denied_syscalls: denied,
        }
    }
}

impl SeccompFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deny_syscall(&mut self, nr: u32) -> &mut Self {
        if !self.denied_syscalls.contains(&nr) {
            self.denied_syscalls.push(nr);
        }
        self
    }

    /// Compiles high-level rule specification into raw BPF bytecode instructions.
    pub fn compile(&self) -> Vec<SockFilter> {
        let mut bpf = vec![
            // 1. Validate architecture (offset 4 in seccomp_data is arch)
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            // [1] Check if arch is x86_64. If false jump to reject
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 1,
                jf: 0,
                k: AUDIT_ARCH_X86_64,
            },
            // [2] Reject unsupported arch
            SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_KILL_PROCESS,
            },
            // [3] Load syscall number (offset 0 in seccomp_data is nr)
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];

        // Deny rule jump table:
        // For each denied syscall, check equality. If equal, return Errno(EPERM), otherwise step to next.
        let num_denied = self.denied_syscalls.len();
        for (i, &syscall_nr) in self.denied_syscalls.iter().enumerate() {
            // If match, jump to the denial RET instruction.
            // Offset to deny instruction: (num_denied - i)
            let jump_offset = (num_denied - i) as u8;
            bpf.push(SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: jump_offset,
                jf: 0,
                k: syscall_nr,
            });
        }

        // Default allow instruction
        bpf.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: self.default_action.to_ret_code(),
        });

        // Deny return instruction (jumped to on match)
        bpf.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SeccompAction::Errno(EPERM as u16).to_ret_code(),
        });

        bpf
    }

    /// Applies the seccomp-bpf filter to the current process thread.
    pub fn apply(&self) -> Result<(), RuntimeError> {
        let filters = self.compile();
        #[cfg(target_os = "linux")]
        let prog = SockFprog {
            len: filters.len() as u16,
            filter: filters.as_ptr(),
        };

        #[cfg(target_os = "linux")]
        {
            unsafe {
                // Ensure no new privileges can be gained via execve setuid
                const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
                if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(RuntimeError::Seccomp(
                        "prctl(PR_SET_NO_NEW_PRIVS) failed".to_string(),
                    ));
                }

                // Load BPF filter
                const PR_SET_SECCOMP: libc::c_int = 22;
                const SECCOMP_MODE_FILTER: libc::c_long = 2;
                if libc::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const SockFprog) != 0 {
                    return Err(RuntimeError::Seccomp(
                        "prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) failed".to_string(),
                    ));
                }
            }
            info!("Applied Seccomp-BPF syscall filters successfully");
        }

        #[cfg(not(target_os = "linux"))]
        {
            debug!(
                rules_count = filters.len(),
                "Seccomp-BPF filters compiled (noop on non-linux)"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_filter_compilation() {
        let mut filter = SeccompFilter::new();
        filter.deny_syscall(999); // custom syscall

        let bytecode = filter.compile();
        assert!(!bytecode.is_empty());

        // Check arch load at instruction 0
        assert_eq!(bytecode[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(bytecode[0].k, 4);

        // Check syscall load at instruction 3
        assert_eq!(bytecode[3].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(bytecode[3].k, 0);

        // Check that apply returns Ok in test environment
        assert!(filter.apply().is_ok());
    }

    #[test]
    fn test_seccomp_action_codes() {
        assert_eq!(SeccompAction::Allow.to_ret_code(), SECCOMP_RET_ALLOW);
        assert_eq!(
            SeccompAction::Errno(1).to_ret_code(),
            SECCOMP_RET_ERRNO | 1
        );
        assert_eq!(
            SeccompAction::KillProcess.to_ret_code(),
            SECCOMP_RET_KILL_PROCESS
        );
    }
}

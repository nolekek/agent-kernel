//! Resource accounting and metrics collector for sandbox isolates.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Real-time metrics snapshot for a sandbox isolate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxMetrics {
    pub session_id: String,
    pub status: String,
    pub uptime_seconds: u64,
    pub cpu_time_ms: u64,
    pub ram_rss_bytes: u64,
    pub disk_layer_bytes: u64,
}

/// Recursively computes total disk size of a directory in bytes.
pub fn compute_dir_size(dir: &Path) -> u64 {
    if !dir.exists() {
        return 0;
    }

    let mut total: u64 = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            } else if path.is_dir() {
                total += compute_dir_size(&path);
            }
        }
    }
    total
}

/// Returns current process Resident Set Size (RAM RSS) in bytes.
pub fn get_process_rss_bytes() -> u64 {
    #[cfg(target_os = "windows")]
    {
        #[repr(C)]
        #[allow(non_snake_case)]
        struct PROCESS_MEMORY_COUNTERS {
            cb: u32,
            PageFaultCount: u32,
            PeakWorkingSetSize: usize,
            WorkingSetSize: usize,
            QuotaPeakPagedPoolUsage: usize,
            QuotaPagedPoolUsage: usize,
            QuotaPeakNonPagedPoolUsage: usize,
            QuotaNonPagedPoolUsage: usize,
            PagefileUsage: usize,
            PeakPagefileUsage: usize,
        }

        extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(
                process: isize,
                pps_mem_counters: *mut PROCESS_MEMORY_COUNTERS,
                cb: u32,
            ) -> i32;
        }

        unsafe {
            let mut pmc = std::mem::zeroed::<PROCESS_MEMORY_COUNTERS>();
            pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            let success = K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb);
            if success != 0 {
                return pmc.WorkingSetSize as u64;
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pages) = parts[1].parse::<u64>() {
                    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
                    return pages * if page_size > 0 { page_size } else { 4096 };
                }
            }
        }
    }

    // Baseline fallback: 16 MB
    16 * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_compute_dir_size() {
        let tmp = tempdir().unwrap();
        let file1 = tmp.path().join("f1.txt");
        let file2 = tmp.path().join("f2.txt");

        fs::write(&file1, b"12345").unwrap(); // 5 bytes
        fs::write(&file2, b"1234567890").unwrap(); // 10 bytes

        let size = compute_dir_size(tmp.path());
        assert_eq!(size, 15);
    }

    #[test]
    fn test_get_process_rss() {
        let rss = get_process_rss_bytes();
        assert!(rss > 0, "RSS must be greater than zero");
    }
}

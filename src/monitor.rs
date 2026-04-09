//! System metrics collection via the `sysinfo` crate.
//! Abstracts OS differences behind a single `SystemMonitor` struct.

use std::collections::HashMap;

use anyhow::Result;
use chrono::Utc;
use sysinfo::{Components, Disks, Networks, System};

use crate::models::{
    CpuMetrics, DiskMetrics, MemoryMetrics, NetworkInterfaceMetrics, OsInfo, ProcessInfo,
    SystemSnapshot, TemperatureReading,
};

// ─── OS Detection ────────────────────────────────────────────────────────────

/// Returns a human-readable OS name detected at compile time.
pub fn detect_os() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "Windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macOS"
    }
    #[cfg(target_os = "linux")]
    {
        "Linux"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        "Unknown OS"
    }
}

/// Returns a descriptive platform string with additional detail.
pub fn platform_info() -> String {
    let os_name = System::name().unwrap_or_else(|| detect_os().to_string());
    let os_ver = System::os_version().unwrap_or_else(|| "?".to_string());
    let kernel = System::kernel_version().unwrap_or_else(|| "?".to_string());
    format!("{os_name} {os_ver} (kernel {kernel})")
}

// ─── Monitor ─────────────────────────────────────────────────────────────────

pub struct SystemMonitor {
    system: System,
    networks: Networks,
    disks: Disks,
    components: Components,
    /// Previous bytes-received per interface for delta calculation.
    prev_rx: HashMap<String, u64>,
    /// Previous bytes-transmitted per interface for delta calculation.
    prev_tx: HashMap<String, u64>,
}

impl SystemMonitor {
    /// Create and warm-up the monitor. Sleeps briefly so the first CPU reading
    /// is non-zero (sysinfo needs two samples for an accurate cpu_usage value).
    pub fn new() -> Self {
        let mut system = System::new_all();
        // First sample – establishes a baseline for CPU usage.
        system.refresh_all();
        std::thread::sleep(std::time::Duration::from_millis(250));
        // Second sample – now cpu_usage() returns a real value.
        system.refresh_cpu_usage();

        Self {
            system,
            networks: Networks::new_with_refreshed_list(),
            disks: Disks::new_with_refreshed_list(),
            components: Components::new_with_refreshed_list(),
            prev_rx: HashMap::new(),
            prev_tx: HashMap::new(),
        }
    }

    /// Refresh all subsystems and return a complete `SystemSnapshot`.
    pub fn collect_snapshot(&mut self) -> Result<SystemSnapshot> {
        self.system.refresh_all();
        self.networks.refresh();
        self.disks.refresh();
        self.components.refresh();

        Ok(SystemSnapshot {
            timestamp: Utc::now(),
            cpu: self.collect_cpu(),
            memory: self.collect_memory(),
            disks: self.collect_disks(),
            network: self.collect_network(),
            processes: self.collect_processes(),
            temperatures: self.collect_temperatures(),
            os_info: self.collect_os_info(),
        })
    }

    // ── CPU ──────────────────────────────────────────────────────────────────

    fn collect_cpu(&self) -> CpuMetrics {
        let cpus = self.system.cpus();
        let per_core: Vec<f32> = cpus.iter().map(|c| c.cpu_usage()).collect();
        let global = if per_core.is_empty() {
            0.0
        } else {
            per_core.iter().sum::<f32>() / per_core.len() as f32
        };
        let (freq, brand) = cpus
            .first()
            .map(|c| (c.frequency(), c.brand().to_string()))
            .unwrap_or((0, "Unknown".to_string()));

        CpuMetrics {
            global_usage_percent: global,
            core_count: per_core.len(),
            per_core_usage: per_core,
            frequency_mhz: freq,
            brand,
        }
    }

    // ── Memory ───────────────────────────────────────────────────────────────

    fn collect_memory(&self) -> MemoryMetrics {
        MemoryMetrics {
            total_bytes: self.system.total_memory(),
            used_bytes: self.system.used_memory(),
            available_bytes: self.system.available_memory(),
            swap_total_bytes: self.system.total_swap(),
            swap_used_bytes: self.system.used_swap(),
        }
    }

    // ── Disks ────────────────────────────────────────────────────────────────

    fn collect_disks(&self) -> Vec<DiskMetrics> {
        self.disks
            .iter()
            .map(|d| DiskMetrics {
                name: d.name().to_string_lossy().to_string(),
                mount_point: d.mount_point().to_string_lossy().to_string(),
                file_system: d.file_system().to_string_lossy().to_string(),
                total_bytes: d.total_space(),
                available_bytes: d.available_space(),
                is_removable: d.is_removable(),
            })
            .collect()
    }

    // ── Network ──────────────────────────────────────────────────────────────

    fn collect_network(&mut self) -> Vec<NetworkInterfaceMetrics> {
        self.networks
            .iter()
            .map(|(name, data)| {
                // `received()` / `transmitted()` are bytes since the last refresh
                // (i.e., already delta values). We also compute totals.
                let rx = data.received();
                let tx = data.transmitted();
                self.prev_rx.insert(name.clone(), rx);
                self.prev_tx.insert(name.clone(), tx);

                NetworkInterfaceMetrics {
                    name: name.clone(),
                    bytes_received: rx,
                    bytes_transmitted: tx,
                    total_bytes_received: data.total_received(),
                    total_bytes_transmitted: data.total_transmitted(),
                    packets_received: data.packets_received(),
                    packets_transmitted: data.packets_transmitted(),
                    errors_received: data.errors_on_received(),
                    errors_transmitted: data.errors_on_transmitted(),
                }
            })
            .collect()
    }

    // ── Processes ────────────────────────────────────────────────────────────

    fn collect_processes(&self) -> Vec<ProcessInfo> {
        self.system
            .processes()
            .iter()
            .map(|(pid, p)| ProcessInfo {
                pid: pid.as_u32(),
                name: p.name().to_string_lossy().to_string(),
                cpu_usage_percent: p.cpu_usage(),
                memory_bytes: p.memory(),
                virtual_memory_bytes: p.virtual_memory(),
                status: format!("{:?}", p.status()),
                exe_path: p.exe().map(|e| e.to_string_lossy().to_string()),
            })
            .collect()
    }

    // ── Temperatures ─────────────────────────────────────────────────────────

    fn collect_temperatures(&self) -> Vec<TemperatureReading> {
        self.components
            .iter()
            .map(|c| TemperatureReading {
                component: c.label().to_string(),
                temperature_celsius: c.temperature(),
                max_celsius: c.max(),
                critical_celsius: c.critical(),
            })
            .collect()
    }

    // ── OS Info ──────────────────────────────────────────────────────────────

    fn collect_os_info(&self) -> OsInfo {
        OsInfo {
            name: System::name().unwrap_or_else(|| detect_os().to_string()),
            version: System::os_version().unwrap_or_else(|| "?".to_string()),
            kernel: System::kernel_version().unwrap_or_else(|| "?".to_string()),
            hostname: System::host_name().unwrap_or_else(|| "?".to_string()),
            uptime_secs: System::uptime(),
        }
    }
}

impl Default for SystemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

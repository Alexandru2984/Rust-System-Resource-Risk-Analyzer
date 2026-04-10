//! Data models shared across all modules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── OS Info ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub kernel: String,
    pub hostname: String,
    pub uptime_secs: u64,
}

// ─── CPU ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpuMetrics {
    pub global_usage_percent: f32,
    pub per_core_usage: Vec<f32>,
    pub core_count: usize,
    pub frequency_mhz: u64,
    pub brand: String,
}

// ─── Memory ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

impl MemoryMetrics {
    pub fn used_percent(&self) -> f32 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        self.used_bytes as f32 / self.total_bytes as f32 * 100.0
    }
    pub fn swap_used_percent(&self) -> f32 {
        if self.swap_total_bytes == 0 {
            return 0.0;
        }
        self.swap_used_bytes as f32 / self.swap_total_bytes as f32 * 100.0
    }
}

// ─── Disk ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskMetrics {
    pub name: String,
    pub mount_point: String,
    pub file_system: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub is_removable: bool,
}

impl DiskMetrics {
    pub fn used_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.available_bytes)
    }
    pub fn used_percent(&self) -> f32 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        self.used_bytes() as f32 / self.total_bytes as f32 * 100.0
    }
}

// ─── Network ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkInterfaceMetrics {
    pub name: String,
    pub bytes_received: u64,
    pub bytes_transmitted: u64,
    pub total_bytes_received: u64,
    pub total_bytes_transmitted: u64,
    pub packets_received: u64,
    pub packets_transmitted: u64,
    pub errors_received: u64,
    pub errors_transmitted: u64,
}

// ─── Process ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_usage_percent: f32,
    pub memory_bytes: u64,
    pub status: String,
}

// ─── Temperature ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TemperatureReading {
    pub component: String,
    pub temperature_celsius: f32,
    pub max_celsius: f32,
    pub critical_celsius: Option<f32>,
}

// ─── Full Snapshot ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub timestamp: DateTime<Utc>,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disks: Vec<DiskMetrics>,
    pub network: Vec<NetworkInterfaceMetrics>,
    pub processes: Vec<ProcessInfo>,
    pub temperatures: Vec<TemperatureReading>,
    pub os_info: OsInfo,
}

// ─── Lightweight snapshot for DB serialisation ────────────────────────────────
//
// Avoids cloning the full `SystemSnapshot` (500+ processes, all interfaces, etc.)
// just to persist the handful of aggregate fields the DB actually needs.

#[derive(Debug, Clone)]
pub struct SnapshotForDb {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub cpu_usage: f32,
    pub memory: MemoryMetrics,
    /// Aggregate RX bytes across all interfaces for this refresh cycle.
    pub net_rx_bytes: u64,
    /// Aggregate TX bytes across all interfaces for this refresh cycle.
    pub net_tx_bytes: u64,
    /// Top-N processes by CPU usage, already sorted and truncated before sending.
    pub top_processes: Vec<ProcessInfo>,
}

// ─── Risk Alerts ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAlert {
    pub id: u64,
    pub timestamp: DateTime<Utc>,
    pub risk_level: RiskLevel,
    pub category: RiskCategory,
    pub description: String,
    pub process_pid: Option<u32>,
    pub process_name: Option<String>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Info => "INFO",
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }
    /// RGBA hex (R,G,B) for use in egui
    pub fn rgb(&self) -> (u8, u8, u8) {
        match self {
            RiskLevel::Info => (100, 149, 237),
            RiskLevel::Low => (50, 200, 50),
            RiskLevel::Medium => (255, 165, 0),
            RiskLevel::High => (255, 69, 0),
            RiskLevel::Critical => (220, 20, 60),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RiskCategory {
    HighCpuGlobal,
    HighMemoryGlobal,
    HighCpuProcess,
    HighMemoryProcess,
    MemoryLeak,
    CriticalTemperature,
    DiskSpaceLow,
    HighNetworkActivity,
    SuspiciousProcess,
}

impl RiskCategory {
    pub fn icon(&self) -> &'static str {
        match self {
            RiskCategory::HighCpuGlobal => "🔥",
            RiskCategory::HighMemoryGlobal => "💾",
            RiskCategory::HighCpuProcess => "⚡",
            RiskCategory::HighMemoryProcess => "🧠",
            RiskCategory::MemoryLeak => "💧",
            RiskCategory::CriticalTemperature => "🌡",
            RiskCategory::DiskSpaceLow => "💿",
            RiskCategory::HighNetworkActivity => "🌐",
            RiskCategory::SuspiciousProcess => "🚨",
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            RiskCategory::HighCpuGlobal => "High Global CPU",
            RiskCategory::HighMemoryGlobal => "High Global Memory",
            RiskCategory::HighCpuProcess => "High CPU Process",
            RiskCategory::HighMemoryProcess => "High Memory Process",
            RiskCategory::MemoryLeak => "Memory Leak Suspected",
            RiskCategory::CriticalTemperature => "Critical Temperature",
            RiskCategory::DiskSpaceLow => "Disk Space Low",
            RiskCategory::HighNetworkActivity => "Unusual Network Activity",
            RiskCategory::SuspiciousProcess => "Suspicious Process",
        }
    }
}

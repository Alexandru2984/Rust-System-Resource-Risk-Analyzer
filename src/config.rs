//! Application configuration with runtime-editable thresholds.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// How often the monitor thread collects a snapshot (milliseconds).
    pub monitoring_interval_ms: u64,
    /// How often snapshots are flushed to the database (seconds).
    pub db_log_interval_secs: u64,
    /// Path to the SQLite database file.
    pub database_path: String,
    /// Maximum data-points kept in the in-memory history ring-buffer.
    pub max_history_points: usize,
    /// Maximum number of alerts kept in memory.
    pub max_alerts: usize,
    /// Alert threshold configuration.
    pub thresholds: AlertThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub cpu_warning_percent: f32,
    pub cpu_critical_percent: f32,
    pub memory_warning_percent: f32,
    pub memory_critical_percent: f32,
    pub disk_warning_percent: f32,
    pub disk_critical_percent: f32,
    pub temp_warning_celsius: f32,
    pub temp_critical_celsius: f32,
    /// Per-process CPU usage that triggers a warning.
    pub process_cpu_warning_percent: f32,
    /// Per-process RSS memory (MB) that triggers a warning.
    pub process_memory_warning_mb: u64,
    /// Minimum consecutive increasing-memory samples to flag a leak.
    pub memory_leak_samples: usize,
    /// Bytes/s per interface that trigger a network alert.
    pub network_bytes_per_sec_threshold: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            monitoring_interval_ms: 2_000,
            db_log_interval_secs: 30,
            database_path: "system_monitor.db".to_string(),
            max_history_points: 60,
            max_alerts: 500,
            thresholds: AlertThresholds::default(),
        }
    }
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            cpu_warning_percent: 75.0,
            cpu_critical_percent: 90.0,
            memory_warning_percent: 75.0,
            memory_critical_percent: 90.0,
            disk_warning_percent: 85.0,
            disk_critical_percent: 95.0,
            temp_warning_celsius: 80.0,
            temp_critical_celsius: 95.0,
            process_cpu_warning_percent: 50.0,
            process_memory_warning_mb: 1_024,
            memory_leak_samples: 5,
            network_bytes_per_sec_threshold: 100 * 1024 * 1024, // 100 MB/s
        }
    }
}

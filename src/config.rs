//! Application configuration with runtime-editable thresholds.
//!
//! Configuration is persisted to / loaded from a TOML file so that user
//! customisations survive application restarts.  The file path is stored
//! inside `AppConfig` itself so the Settings panel can show and change it.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

// ─── Top-level config ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// How often the monitor thread collects a snapshot (milliseconds).
    pub monitoring_interval_ms: u64,
    /// How often snapshots are flushed to the database (seconds).
    pub db_log_interval_secs: u64,
    /// Path to the SQLite database file.
    pub database_path: String,
    /// Path to this TOML config file (empty = not yet saved).
    pub config_path: String,
    /// Maximum data-points kept in the in-memory history ring-buffer.
    pub max_history_points: usize,
    /// Maximum number of alerts kept in memory.
    pub max_alerts: usize,
    /// Alert threshold configuration.
    pub thresholds: AlertThresholds,
}

// ─── Alert thresholds ────────────────────────────────────────────────────────

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
    /// How long (seconds) the same (category, subject) alert is suppressed
    /// after being emitted once.  Prevents alert floods.
    pub dedup_window_secs: u64,
}

// ─── Default impls ───────────────────────────────────────────────────────────

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            monitoring_interval_ms: 2_000,
            db_log_interval_secs: 30,
            database_path: "system_monitor.db".to_string(),
            config_path: "system_analyzer.toml".to_string(),
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
            dedup_window_secs: 60,
        }
    }
}

// ─── TOML persistence ────────────────────────────────────────────────────────

impl AppConfig {
    /// Load an `AppConfig` from a TOML file.
    ///
    /// If the file does not exist, returns `Ok(AppConfig::default())` and
    /// records `path` as the future save location.
    pub fn load(path: &str) -> Result<Self> {
        if !Path::new(path).exists() {
            log::info!("Config file '{path}' not found – using defaults.");
            let mut cfg = AppConfig::default();
            cfg.config_path = path.to_string();
            return Ok(cfg);
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read config file '{path}'"))?;

        let mut cfg: AppConfig =
            toml::from_str(&raw).with_context(|| format!("Cannot parse config file '{path}'"))?;

        // Always keep config_path in sync with what was actually loaded.
        cfg.config_path = path.to_string();
        log::info!("Config loaded from '{path}'.");
        Ok(cfg)
    }

    /// Save the current `AppConfig` to its `config_path` as TOML.
    pub fn save(&self) -> Result<()> {
        let toml_str =
            toml::to_string_pretty(self).context("Failed to serialise config to TOML")?;

        std::fs::write(&self.config_path, toml_str)
            .with_context(|| format!("Cannot write config to '{}'", self.config_path))?;

        log::info!("Config saved to '{}'.", self.config_path);
        Ok(())
    }

    /// Save to a new path and update `config_path`.
    pub fn save_as(&mut self, path: &str) -> Result<()> {
        self.config_path = path.to_string();
        self.save()
    }
}

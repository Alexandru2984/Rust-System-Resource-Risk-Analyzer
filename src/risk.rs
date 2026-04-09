//! Risk analysis engine.
//!
//! The `RiskAnalyzer` consumes a `SystemSnapshot` and emits zero or more
//! `RiskAlert`s.  Alerts are deduplicated within a configurable time-window so
//! the same condition does not produce an avalanche of identical entries.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::config::AlertThresholds;
use crate::models::{RiskAlert, RiskCategory, RiskLevel, SystemSnapshot};

// ─── Known suspicious process name fragments ─────────────────────────────────

const SUSPICIOUS_NAMES: &[&str] = &[
    "xmrig",
    "cryptominer",
    "coinhive",
    "cpuminer",
    "minerd",
    "mimikatz",
    "meterpreter",
    "nc.exe",
    "netcat",
    "ncat",
    "masscan",
    "zmap",
    "nmap",
    "keylogger",
    "rootkit",
    "backdoor",
    "cryptonight",
    "stratum+tcp",
];

// ─── Dedup key ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct AlertKey {
    category: String,
    subject: String, // process name or component name or "global"
}

// ─── Risk Analyzer ───────────────────────────────────────────────────────────

pub struct RiskAnalyzer {
    thresholds: AlertThresholds,
    next_id: u64,
    /// Tracks when each (category, subject) alert was last emitted to avoid
    /// flooding the UI with identical consecutive alerts.
    last_emitted: HashMap<AlertKey, Instant>,
    dedup_window: Duration,
    /// Per-PID memory history used to detect growing (leaking) processes.
    mem_history: HashMap<u32, VecDeque<u64>>,
}

impl RiskAnalyzer {
    pub fn new(thresholds: AlertThresholds) -> Self {
        Self {
            thresholds,
            next_id: 1,
            last_emitted: HashMap::new(),
            dedup_window: Duration::from_secs(60),
            mem_history: HashMap::new(),
        }
    }

    /// Update thresholds at runtime (called from Settings panel).
    pub fn update_thresholds(&mut self, thresholds: AlertThresholds) {
        self.thresholds = thresholds;
    }

    // ── Main entry-point ─────────────────────────────────────────────────────

    /// Analyse a snapshot and return newly-generated alerts.
    pub fn analyse(&mut self, snapshot: &SystemSnapshot) -> Vec<RiskAlert> {
        let mut alerts = Vec::new();

        self.check_global_cpu(snapshot, &mut alerts);
        self.check_global_memory(snapshot, &mut alerts);
        self.check_disks(snapshot, &mut alerts);
        self.check_temperatures(snapshot, &mut alerts);
        self.check_network(snapshot, &mut alerts);
        self.check_processes(snapshot, &mut alerts);

        alerts
    }

    // ── Global CPU ───────────────────────────────────────────────────────────

    fn check_global_cpu(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        let usage = snapshot.cpu.global_usage_percent;
        let (level, threshold) = if usage >= self.thresholds.cpu_critical_percent {
            (RiskLevel::Critical, self.thresholds.cpu_critical_percent)
        } else if usage >= self.thresholds.cpu_warning_percent {
            (RiskLevel::High, self.thresholds.cpu_warning_percent)
        } else {
            return;
        };

        let key = AlertKey {
            category: "HighCpuGlobal".to_string(),
            subject: "global".to_string(),
        };
        if self.should_emit(&key) {
            out.push(self.make_alert(
                level,
                RiskCategory::HighCpuGlobal,
                format!(
                    "Global CPU usage is {:.1}% (threshold: {:.0}%)",
                    usage, threshold
                ),
                None,
                None,
            ));
        }
    }

    // ── Global Memory ────────────────────────────────────────────────────────

    fn check_global_memory(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        let pct = snapshot.memory.used_percent();
        let (level, threshold) = if pct >= self.thresholds.memory_critical_percent {
            (RiskLevel::Critical, self.thresholds.memory_critical_percent)
        } else if pct >= self.thresholds.memory_warning_percent {
            (RiskLevel::High, self.thresholds.memory_warning_percent)
        } else {
            return;
        };

        let key = AlertKey {
            category: "HighMemoryGlobal".to_string(),
            subject: "global".to_string(),
        };
        if self.should_emit(&key) {
            out.push(self.make_alert(
                level,
                RiskCategory::HighMemoryGlobal,
                format!(
                    "RAM usage is {:.1}% – {:.1}/{:.1} GB used (threshold: {:.0}%)",
                    pct,
                    snapshot.memory.used_bytes as f64 / 1e9,
                    snapshot.memory.total_bytes as f64 / 1e9,
                    threshold,
                ),
                None,
                None,
            ));
        }
    }

    // ── Disks ────────────────────────────────────────────────────────────────

    fn check_disks(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        for disk in &snapshot.disks {
            let pct = disk.used_percent();
            let (level, threshold) = if pct >= self.thresholds.disk_critical_percent {
                (RiskLevel::Critical, self.thresholds.disk_critical_percent)
            } else if pct >= self.thresholds.disk_warning_percent {
                (RiskLevel::Medium, self.thresholds.disk_warning_percent)
            } else {
                continue;
            };

            let key = AlertKey {
                category: "DiskSpaceLow".to_string(),
                subject: disk.mount_point.clone(),
            };
            if self.should_emit(&key) {
                out.push(self.make_alert(
                    level,
                    RiskCategory::DiskSpaceLow,
                    format!(
                        "Disk '{}' ({}) is {:.1}% full – {:.1} GB free (threshold: {:.0}%)",
                        disk.name,
                        disk.mount_point,
                        pct,
                        disk.available_bytes as f64 / 1e9,
                        threshold,
                    ),
                    None,
                    None,
                ));
            }
        }
    }

    // ── Temperatures ─────────────────────────────────────────────────────────

    fn check_temperatures(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        for temp in &snapshot.temperatures {
            // Prefer the hardware-reported critical threshold if available.
            let hw_critical = temp.critical_celsius.unwrap_or(f32::MAX);
            let cfg_critical = self.thresholds.temp_critical_celsius;
            let cfg_warning = self.thresholds.temp_warning_celsius;

            let (level, threshold) = if temp.temperature_celsius >= hw_critical.min(cfg_critical) {
                (RiskLevel::Critical, hw_critical.min(cfg_critical))
            } else if temp.temperature_celsius >= cfg_warning {
                (RiskLevel::High, cfg_warning)
            } else {
                continue;
            };

            let key = AlertKey {
                category: "CriticalTemperature".to_string(),
                subject: temp.component.clone(),
            };
            if self.should_emit(&key) {
                out.push(self.make_alert(
                    level,
                    RiskCategory::CriticalTemperature,
                    format!(
                        "Component '{}' is at {:.1}°C (threshold: {:.0}°C)",
                        temp.component, temp.temperature_celsius, threshold,
                    ),
                    None,
                    None,
                ));
            }
        }
    }

    // ── Network ──────────────────────────────────────────────────────────────

    fn check_network(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        let interval_secs = 2.0_f64; // nominal monitoring interval
        for iface in &snapshot.network {
            let rx_bps = iface.bytes_received as f64 / interval_secs;
            let tx_bps = iface.bytes_transmitted as f64 / interval_secs;
            let threshold = self.thresholds.network_bytes_per_sec_threshold as f64;

            if rx_bps > threshold || tx_bps > threshold {
                let key = AlertKey {
                    category: "HighNetworkActivity".to_string(),
                    subject: iface.name.clone(),
                };
                if self.should_emit(&key) {
                    out.push(self.make_alert(
                        RiskLevel::Medium,
                        RiskCategory::HighNetworkActivity,
                        format!(
                            "Interface '{}': RX {:.1} MB/s / TX {:.1} MB/s (threshold: {:.0} MB/s)",
                            iface.name,
                            rx_bps / 1e6,
                            tx_bps / 1e6,
                            threshold / 1e6,
                        ),
                        None,
                        None,
                    ));
                }
            }
        }
    }

    // ── Processes ────────────────────────────────────────────────────────────

    fn check_processes(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        // Clean up PID history for processes that no longer exist.
        let live_pids: HashSet<u32> = snapshot.processes.iter().map(|p| p.pid).collect();
        self.mem_history.retain(|pid, _| live_pids.contains(pid));

        for proc in &snapshot.processes {
            self.check_process_cpu(proc, out);
            self.check_process_memory(proc, out);
            self.check_memory_leak(proc, out);
            self.check_suspicious_name(proc, out);
        }
    }

    fn check_process_cpu(&mut self, proc: &crate::models::ProcessInfo, out: &mut Vec<RiskAlert>) {
        if proc.cpu_usage_percent < self.thresholds.process_cpu_warning_percent {
            return;
        }
        let level = if proc.cpu_usage_percent >= 80.0 {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
        let key = AlertKey {
            category: "HighCpuProcess".to_string(),
            subject: proc.pid.to_string(),
        };
        if self.should_emit(&key) {
            out.push(self.make_alert(
                level,
                RiskCategory::HighCpuProcess,
                format!(
                    "Process '{}' (PID {}) is using {:.1}% CPU",
                    proc.name, proc.pid, proc.cpu_usage_percent,
                ),
                Some(proc.pid),
                Some(proc.name.clone()),
            ));
        }
    }

    fn check_process_memory(
        &mut self,
        proc: &crate::models::ProcessInfo,
        out: &mut Vec<RiskAlert>,
    ) {
        let mem_mb = proc.memory_bytes / (1024 * 1024);
        if mem_mb < self.thresholds.process_memory_warning_mb {
            return;
        }
        let level = if mem_mb >= self.thresholds.process_memory_warning_mb * 2 {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        };
        let key = AlertKey {
            category: "HighMemoryProcess".to_string(),
            subject: proc.pid.to_string(),
        };
        if self.should_emit(&key) {
            out.push(self.make_alert(
                level,
                RiskCategory::HighMemoryProcess,
                format!(
                    "Process '{}' (PID {}) is consuming {} MB of RAM (threshold: {} MB)",
                    proc.name, proc.pid, mem_mb, self.thresholds.process_memory_warning_mb,
                ),
                Some(proc.pid),
                Some(proc.name.clone()),
            ));
        }
    }

    fn check_memory_leak(&mut self, proc: &crate::models::ProcessInfo, out: &mut Vec<RiskAlert>) {
        let history = self
            .mem_history
            .entry(proc.pid)
            .or_insert_with(|| VecDeque::with_capacity(10));

        history.push_back(proc.memory_bytes);
        if history.len() > 10 {
            history.pop_front();
        }

        let n = self.thresholds.memory_leak_samples;
        if history.len() < n {
            return;
        }

        // Check if the last `n` samples are strictly increasing.
        let tail: Vec<u64> = history.iter().rev().take(n).cloned().collect();
        let consistently_growing = tail.windows(2).all(|w| w[0] > w[1]);

        if !consistently_growing {
            return;
        }

        let growth_mb = (tail[0].saturating_sub(*tail.last().unwrap())) / (1024 * 1024);
        if growth_mb == 0 {
            return;
        }

        let key = AlertKey {
            category: "MemoryLeak".to_string(),
            subject: proc.pid.to_string(),
        };
        if self.should_emit(&key) {
            out.push(self.make_alert(
                RiskLevel::High,
                RiskCategory::MemoryLeak,
                format!(
                    "Process '{}' (PID {}) memory grew +{} MB over {} samples – possible leak",
                    proc.name, proc.pid, growth_mb, n,
                ),
                Some(proc.pid),
                Some(proc.name.clone()),
            ));
        }
    }

    fn check_suspicious_name(
        &mut self,
        proc: &crate::models::ProcessInfo,
        out: &mut Vec<RiskAlert>,
    ) {
        let name_lower = proc.name.to_lowercase();
        for pattern in SUSPICIOUS_NAMES {
            if name_lower.contains(pattern) {
                let key = AlertKey {
                    category: "SuspiciousProcess".to_string(),
                    subject: proc.pid.to_string(),
                };
                if self.should_emit(&key) {
                    out.push(self.make_alert(
                        RiskLevel::Critical,
                        RiskCategory::SuspiciousProcess,
                        format!(
                            "Suspicious process detected: '{}' (PID {}) matches pattern '{}'",
                            proc.name, proc.pid, pattern,
                        ),
                        Some(proc.pid),
                        Some(proc.name.clone()),
                    ));
                }
                break; // one alert per process per window
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Returns `true` if enough time has passed since the last alert with
    /// the same key (deduplication window).
    fn should_emit(&mut self, key: &AlertKey) -> bool {
        let now = Instant::now();
        match self.last_emitted.get(key) {
            Some(&last) if now.duration_since(last) < self.dedup_window => false,
            _ => {
                self.last_emitted.insert(key.clone(), now);
                true
            }
        }
    }

    fn make_alert(
        &mut self,
        level: RiskLevel,
        category: RiskCategory,
        desc: String,
        pid: Option<u32>,
        pname: Option<String>,
    ) -> RiskAlert {
        let id = self.next_id;
        self.next_id += 1;
        RiskAlert {
            id,
            timestamp: Utc::now(),
            risk_level: level,
            category,
            description: desc,
            process_pid: pid,
            process_name: pname,
            acknowledged: false,
        }
    }
}

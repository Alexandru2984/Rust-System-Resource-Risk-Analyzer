//! Risk analysis engine.
//!
//! The `RiskAnalyzer` consumes a `SystemSnapshot` and emits zero or more
//! `RiskAlert`s. Alerts are deduplicated within a configurable time-window so
//! the same condition does not produce an avalanche of identical entries.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::config::AlertThresholds;
use crate::models::{ProcessInfo, RiskAlert, RiskCategory, RiskLevel, SystemSnapshot};

// ─── Suspicious process patterns ─────────────────────────────────────────────

/// Clear malware / post-exploitation indicators -> Critical.
const CRITICAL_PATTERNS: &[&str] = &[
    "xmrig",
    "cryptominer",
    "coinhive",
    "cpuminer",
    "minerd",
    "mimikatz",
    "meterpreter",
    "rootkit",
    "backdoor",
    "cryptonight",
    "stratum+tcp",
];

/// Dual-use tooling -> Medium. These may be legitimate on admin/security hosts.
const POTENTIALLY_SUSPICIOUS_PATTERNS: &[&str] = &[
    "masscan", "zmap", "nmap", "netcat", "ncat", "nc.exe", "socat",
];

// ─── Dedup key ───────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct AlertKey {
    category: String,
    subject: String,
}

// ─── Risk Analyzer ───────────────────────────────────────────────────────────

pub struct RiskAnalyzer {
    thresholds: AlertThresholds,
    next_id: u64,
    /// Tracks when each (category, subject) alert was last emitted.
    last_emitted: HashMap<AlertKey, Instant>,
    dedup_window: Duration,
    /// Per-process RSS history keyed by (pid, process_name) to avoid PID reuse
    /// false-positives.
    mem_history: HashMap<(u32, String), VecDeque<u64>>,
    /// Periodic cleanup timestamp for internal maps.
    last_cleanup: Instant,
}

impl RiskAnalyzer {
    pub fn new(thresholds: AlertThresholds) -> Self {
        let dedup_window = Duration::from_secs(thresholds.dedup_window_secs.max(1));
        Self {
            thresholds,
            next_id: 1,
            last_emitted: HashMap::new(),
            dedup_window,
            mem_history: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Update thresholds at runtime.
    pub fn update_thresholds(&mut self, thresholds: AlertThresholds) {
        self.dedup_window = Duration::from_secs(thresholds.dedup_window_secs.max(1));
        self.thresholds = thresholds;
    }

    /// Analyse a snapshot and return newly-generated alerts.
    ///
    /// `interval_ms` must be the active monitor interval so network throughput
    /// is computed correctly when the user changes settings at runtime.
    pub fn analyse(&mut self, snapshot: &SystemSnapshot, interval_ms: u64) -> Vec<RiskAlert> {
        if self.last_cleanup.elapsed() >= Duration::from_secs(300) {
            self.cleanup_stale_state(snapshot);
            self.last_cleanup = Instant::now();
        }

        let mut alerts = Vec::new();

        self.check_global_cpu(snapshot, &mut alerts);
        self.check_global_memory(snapshot, &mut alerts);
        self.check_disks(snapshot, &mut alerts);
        self.check_temperatures(snapshot, &mut alerts);
        self.check_network(snapshot, interval_ms, &mut alerts);
        self.check_processes(snapshot, &mut alerts);

        alerts
    }

    fn cleanup_stale_state(&mut self, snapshot: &SystemSnapshot) {
        let now = Instant::now();
        let max_age = self.dedup_window + self.dedup_window;

        self.last_emitted
            .retain(|_, last| now.duration_since(*last) <= max_age);

        let live: HashSet<(u32, String)> = snapshot
            .processes
            .iter()
            .map(|p| (p.pid, p.name.clone()))
            .collect();
        self.mem_history.retain(|key, _| live.contains(key));
    }

    fn check_global_cpu(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        let usage = snapshot.cpu.global_usage_percent;
        if !usage.is_finite() {
            return;
        }

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

    fn check_temperatures(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        for temp in &snapshot.temperatures {
            if !temp.temperature_celsius.is_finite() {
                continue;
            }

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

    fn check_network(
        &mut self,
        snapshot: &SystemSnapshot,
        interval_ms: u64,
        out: &mut Vec<RiskAlert>,
    ) {
        let interval_secs = (interval_ms.max(1) as f64) / 1000.0;

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

    fn check_processes(&mut self, snapshot: &SystemSnapshot, out: &mut Vec<RiskAlert>) {
        let live: HashSet<(u32, String)> = snapshot
            .processes
            .iter()
            .map(|p| (p.pid, p.name.clone()))
            .collect();
        self.mem_history.retain(|key, _| live.contains(key));

        for proc in &snapshot.processes {
            self.check_process_cpu(proc, out);
            self.check_process_memory(proc, out);
            self.check_memory_leak(proc, out);
            self.check_suspicious_name(proc, out);
        }
    }

    fn check_process_cpu(&mut self, proc: &ProcessInfo, out: &mut Vec<RiskAlert>) {
        if !proc.cpu_usage_percent.is_finite() {
            return;
        }
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

    fn check_process_memory(&mut self, proc: &ProcessInfo, out: &mut Vec<RiskAlert>) {
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

    fn check_memory_leak(&mut self, proc: &ProcessInfo, out: &mut Vec<RiskAlert>) {
        let history = self
            .mem_history
            .entry((proc.pid, proc.name.clone()))
            .or_insert_with(|| VecDeque::with_capacity(10));

        history.push_back(proc.memory_bytes);
        if history.len() > 10 {
            history.pop_front();
        }

        let n = self.thresholds.memory_leak_samples;
        if history.len() < n {
            return;
        }

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
            subject: format!("{}:{}", proc.pid, proc.name),
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

    fn check_suspicious_name(&mut self, proc: &ProcessInfo, out: &mut Vec<RiskAlert>) {
        let name_lower = proc.name.to_lowercase();

        for pattern in CRITICAL_PATTERNS {
            if name_lower.contains(pattern) {
                let key = AlertKey {
                    category: "SuspiciousProcessCritical".to_string(),
                    subject: proc.pid.to_string(),
                };
                if self.should_emit(&key) {
                    out.push(self.make_alert(
                        RiskLevel::Critical,
                        RiskCategory::SuspiciousProcess,
                        format!(
                            "Suspicious process detected: '{}' (PID {}) matches critical pattern '{}'",
                            proc.name, proc.pid, pattern,
                        ),
                        Some(proc.pid),
                        Some(proc.name.clone()),
                    ));
                }
                return;
            }
        }

        for pattern in POTENTIALLY_SUSPICIOUS_PATTERNS {
            let matched = if pattern.len() <= 5 {
                name_lower == *pattern || name_lower == format!("{}.exe", pattern)
            } else {
                name_lower.contains(pattern)
            };

            if matched {
                let key = AlertKey {
                    category: "SuspiciousProcessPotential".to_string(),
                    subject: proc.pid.to_string(),
                };
                if self.should_emit(&key) {
                    out.push(self.make_alert(
                        RiskLevel::Medium,
                        RiskCategory::SuspiciousProcess,
                        format!(
                            "Potentially suspicious tool detected: '{}' (PID {}) matches '{}'",
                            proc.name, proc.pid, pattern,
                        ),
                        Some(proc.pid),
                        Some(proc.name.clone()),
                    ));
                }
                return;
            }
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        CpuMetrics, MemoryMetrics, NetworkInterfaceMetrics, OsInfo, ProcessInfo, SystemSnapshot,
    };

    fn mk_proc(pid: u32, name: &str, memory_mb: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            cpu_usage_percent: 0.0,
            memory_bytes: memory_mb * 1024 * 1024,
            status: "Run".to_string(),
        }
    }

    fn snapshot_with_processes(processes: Vec<ProcessInfo>) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            cpu: CpuMetrics {
                global_usage_percent: 10.0,
                ..Default::default()
            },
            memory: MemoryMetrics {
                total_bytes: 16 * 1024 * 1024 * 1024,
                used_bytes: 8 * 1024 * 1024 * 1024,
                available_bytes: 8 * 1024 * 1024 * 1024,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            },
            disks: vec![],
            network: vec![],
            processes,
            temperatures: vec![],
            os_info: OsInfo::default(),
        }
    }

    fn snapshot_with_network(rx_bytes: u64, tx_bytes: u64) -> SystemSnapshot {
        SystemSnapshot {
            timestamp: Utc::now(),
            cpu: CpuMetrics {
                global_usage_percent: 10.0,
                ..Default::default()
            },
            memory: MemoryMetrics {
                total_bytes: 16 * 1024 * 1024 * 1024,
                used_bytes: 8 * 1024 * 1024 * 1024,
                available_bytes: 8 * 1024 * 1024 * 1024,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            },
            disks: vec![],
            network: vec![NetworkInterfaceMetrics {
                name: "eth0".to_string(),
                bytes_received: rx_bytes,
                bytes_transmitted: tx_bytes,
                total_bytes_received: rx_bytes,
                total_bytes_transmitted: tx_bytes,
                packets_received: 0,
                packets_transmitted: 0,
                errors_received: 0,
                errors_transmitted: 0,
            }],
            processes: vec![],
            temperatures: vec![],
            os_info: OsInfo::default(),
        }
    }

    fn snapshot_with_named_process(name: &str) -> SystemSnapshot {
        snapshot_with_processes(vec![mk_proc(4321, name, 64)])
    }

    #[test]
    fn pid_reuse_different_name_does_not_inherit_memory_history() {
        let mut thresholds = AlertThresholds::default();
        thresholds.memory_leak_samples = 4;
        thresholds.process_memory_warning_mb = u64::MAX;
        let mut analyzer = RiskAnalyzer::new(thresholds);

        for mb in [100, 120, 140, 160] {
            let snap = snapshot_with_processes(vec![mk_proc(1234, "proc_a", mb)]);
            let _ = analyzer.analyse(&snap, 2000);
        }

        let snap = snapshot_with_processes(vec![mk_proc(1234, "proc_b", 50)]);
        let alerts = analyzer.analyse(&snap, 2000);

        assert!(
            !alerts
                .iter()
                .any(|a| a.category == RiskCategory::MemoryLeak),
            "PID reuse with different name must not inherit memory leak history"
        );
    }

    #[test]
    fn dedup_suppresses_repeated_global_cpu_alerts() {
        let mut thresholds = AlertThresholds::default();
        thresholds.cpu_warning_percent = 50.0;
        thresholds.cpu_critical_percent = 90.0;
        thresholds.dedup_window_secs = 60;

        let mut analyzer = RiskAnalyzer::new(thresholds);

        let mut first_snapshot = snapshot_with_processes(vec![]);
        first_snapshot.cpu.global_usage_percent = 80.0;

        let first_alerts = analyzer.analyse(&first_snapshot, 2000);
        assert!(
            first_alerts
                .iter()
                .any(|a| a.category == RiskCategory::HighCpuGlobal),
            "first high CPU sample should emit an alert"
        );

        let second_alerts = analyzer.analyse(&first_snapshot, 2000);
        assert!(
            !second_alerts
                .iter()
                .any(|a| a.category == RiskCategory::HighCpuGlobal),
            "second sample inside dedup window should be suppressed"
        );
    }

    #[test]
    fn network_threshold_respects_runtime_interval_ms() {
        let mut thresholds = AlertThresholds::default();
        thresholds.network_bytes_per_sec_threshold = 4_000_000;
        let mut analyzer = RiskAnalyzer::new(thresholds);

        let snapshot = snapshot_with_network(10_000_000, 0);

        let alerts_fast_interval = analyzer.analyse(&snapshot, 2000);
        assert!(
            alerts_fast_interval
                .iter()
                .any(|a| a.category == RiskCategory::HighNetworkActivity),
            "10 MB over 2s should exceed 4 MB/s threshold"
        );

        let mut thresholds = AlertThresholds::default();
        thresholds.network_bytes_per_sec_threshold = 6_000_000;
        thresholds.dedup_window_secs = 0;
        let mut analyzer = RiskAnalyzer::new(thresholds);

        let alerts_slow_interval = analyzer.analyse(&snapshot, 5000);
        assert!(
            !alerts_slow_interval
                .iter()
                .any(|a| a.category == RiskCategory::HighNetworkActivity),
            "10 MB over 5s is only 2 MB/s and should stay below 6 MB/s threshold"
        );
    }

    #[test]
    fn suspicious_name_matching_does_not_false_positive_on_vnmapper() {
        let thresholds = AlertThresholds::default();
        let mut analyzer = RiskAnalyzer::new(thresholds);

        let snapshot = snapshot_with_named_process("vnmapper");
        let alerts = analyzer.analyse(&snapshot, 2000);

        assert!(
            !alerts
                .iter()
                .any(|a| a.category == RiskCategory::SuspiciousProcess),
            "vnmapper must not match the short exact-name rule for nmap"
        );
    }

    #[test]
    fn suspicious_name_matching_flags_exact_nmap_as_medium() {
        let thresholds = AlertThresholds::default();
        let mut analyzer = RiskAnalyzer::new(thresholds);

        let snapshot = snapshot_with_named_process("nmap");
        let alerts = analyzer.analyse(&snapshot, 2000);

        let alert = alerts
            .iter()
            .find(|a| a.category == RiskCategory::SuspiciousProcess)
            .expect("exact nmap process name should trigger suspicious process alert");

        assert_eq!(
            alert.risk_level,
            RiskLevel::Medium,
            "dual-use tools like nmap should be medium severity, not critical"
        );
    }

    #[test]
    fn increasing_memory_triggers_memory_leak_alert() {
        let mut thresholds = AlertThresholds::default();
        thresholds.memory_leak_samples = 4;
        thresholds.process_memory_warning_mb = u64::MAX;
        thresholds.dedup_window_secs = 60;

        let mut analyzer = RiskAnalyzer::new(thresholds);

        let mut alerts = Vec::new();
        for mb in [100, 120, 140, 160] {
            let snapshot = snapshot_with_processes(vec![mk_proc(7777, "leaky_proc", mb)]);
            alerts = analyzer.analyse(&snapshot, 2000);
        }

        let leak_alert = alerts
            .iter()
            .find(|a| a.category == RiskCategory::MemoryLeak)
            .expect("strictly increasing memory samples should trigger a memory leak alert");

        assert_eq!(leak_alert.risk_level, RiskLevel::High);
        assert_eq!(leak_alert.process_pid, Some(7777));
        assert_eq!(leak_alert.process_name.as_deref(), Some("leaky_proc"));
    }
}

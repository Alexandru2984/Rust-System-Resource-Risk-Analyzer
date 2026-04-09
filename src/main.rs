//! Entry point for the System Resource & Risk Analyzer.
//!
//! ## Thread architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  main thread                                                  │
//! │  eframe::run_native() – GUI render loop (egui)               │
//! │  reads/writes AppState through Arc<Mutex<AppState>>           │
//! └───────────────────────────┬──────────────────────────────────┘
//!                             │ Arc<Mutex<AppState>>
//! ┌───────────────────────────▼──────────────────────────────────┐
//! │  monitor_thread                                               │
//! │  SystemMonitor::collect_snapshot()  every N ms               │
//! │  RiskAnalyzer::analyse()                                      │
//! │  pushes snapshots + alerts into AppState                      │
//! │  sends DbMessage to db_thread via mpsc::channel               │
//! └───────────────────────────┬──────────────────────────────────┘
//!                             │ mpsc channel
//! ┌───────────────────────────▼──────────────────────────────────┐
//! │  db_thread                                                    │
//! │  owns rusqlite::Connection (not Send – lives in this thread)  │
//! │  Database::insert_snapshot() / insert_alert()                 │
//! └──────────────────────────────────────────────────────────────┘
//! ```

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod database;
mod errors;
mod gui;
mod models;
mod monitor;
mod risk;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;

use config::AppConfig;
use database::Database;
use models::{RiskAlert, SystemSnapshot};
use monitor::SystemMonitor;
use risk::RiskAnalyzer;

// ─── Shared application state ─────────────────────────────────────────────────

/// All mutable data shared between the GUI and the monitor thread.
pub struct AppState {
    /// The most recently collected system snapshot.
    pub latest_snapshot: Option<SystemSnapshot>,
    /// Ring-buffer of per-sample global CPU usage (%) for the history graph.
    pub cpu_history: VecDeque<f32>,
    /// Ring-buffer of per-sample RAM usage (%) for the history graph.
    pub mem_history: VecDeque<f32>,
    /// Ring-buffer of aggregate network RX bytes per refresh interval.
    pub net_rx_history: VecDeque<f64>,
    /// Ring-buffer of aggregate network TX bytes per refresh interval.
    pub net_tx_history: VecDeque<f64>,
    /// All active risk alerts (capped at config.max_alerts).
    pub alerts: Vec<RiskAlert>,
    /// Runtime-editable configuration (read by monitor thread each cycle).
    pub config: AppConfig,
    /// Total snapshots persisted to the database (informational counter).
    pub db_snapshot_count: i64,
    /// Short status string shown in the title bar.
    pub status: String,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let max = config.max_history_points;
        Self {
            latest_snapshot: None,
            cpu_history: VecDeque::with_capacity(max),
            mem_history: VecDeque::with_capacity(max),
            net_rx_history: VecDeque::with_capacity(max),
            net_tx_history: VecDeque::with_capacity(max),
            alerts: Vec::new(),
            config,
            db_snapshot_count: 0,
            status: "Initialising…".to_string(),
        }
    }

    /// Integrate a new snapshot (and any resulting alerts) into the shared state.
    pub fn ingest(&mut self, snapshot: SystemSnapshot, new_alerts: Vec<RiskAlert>) {
        let max = self.config.max_history_points;

        push_capped(
            &mut self.cpu_history,
            snapshot.cpu.global_usage_percent,
            max,
        );
        push_capped(&mut self.mem_history, snapshot.memory.used_percent(), max);

        let rx: f64 = snapshot
            .network
            .iter()
            .map(|n| n.bytes_received as f64)
            .sum();
        let tx: f64 = snapshot
            .network
            .iter()
            .map(|n| n.bytes_transmitted as f64)
            .sum();
        push_capped(&mut self.net_rx_history, rx, max);
        push_capped(&mut self.net_tx_history, tx, max);

        for alert in new_alerts {
            log::warn!("[{:?}] {}", alert.risk_level, alert.description);
            self.alerts.push(alert);
        }
        let max_alerts = self.config.max_alerts;
        if self.alerts.len() > max_alerts {
            let excess = self.alerts.len() - max_alerts;
            self.alerts.drain(0..excess);
        }

        self.latest_snapshot = Some(snapshot);
        self.status = format!("Running  –  {} snapshots in DB", self.db_snapshot_count);
    }
}

fn push_capped<T>(dq: &mut VecDeque<T>, value: T, max: usize) {
    if dq.len() >= max {
        dq.pop_front();
    }
    dq.push_back(value);
}

// ─── Database message ─────────────────────────────────────────────────────────

enum DbMessage {
    Snapshot(SystemSnapshot),
    Alert(RiskAlert),
    IncrSnapshotCount,
}

// ─── Monitor thread ───────────────────────────────────────────────────────────

fn monitor_thread(state: Arc<Mutex<AppState>>, db_tx: std::sync::mpsc::SyncSender<DbMessage>) {
    log::info!("Monitor thread started  (OS: {})", monitor::platform_info());

    let initial_thresholds = { state.lock().unwrap().config.thresholds.clone() };
    let mut sys_monitor = SystemMonitor::new();
    let mut risk_analyzer = RiskAnalyzer::new(initial_thresholds);
    let mut last_db_write = Instant::now() - Duration::from_secs(999); // force first write

    loop {
        // Read current config without holding the lock during I/O.
        let (interval_ms, db_interval_secs, thresholds) = {
            let s = state.lock().unwrap();
            (
                s.config.monitoring_interval_ms,
                s.config.db_log_interval_secs,
                s.config.thresholds.clone(),
            )
        };
        risk_analyzer.update_thresholds(thresholds);

        match sys_monitor.collect_snapshot() {
            Ok(snapshot) => {
                let new_alerts = risk_analyzer.analyse(&snapshot);

                // Push to DB thread at the configured interval.
                if last_db_write.elapsed().as_secs() >= db_interval_secs {
                    let _ = db_tx.try_send(DbMessage::Snapshot(snapshot.clone()));
                    let _ = db_tx.try_send(DbMessage::IncrSnapshotCount);
                    last_db_write = Instant::now();
                }
                for alert in &new_alerts {
                    let _ = db_tx.try_send(DbMessage::Alert(alert.clone()));
                }

                // Update shared GUI state.
                if let Ok(mut s) = state.lock() {
                    s.ingest(snapshot, new_alerts);
                }
            }
            Err(e) => {
                log::error!("Snapshot collection failed: {e}");
                if let Ok(mut s) = state.lock() {
                    s.status = format!("ERROR: {e}");
                }
            }
        }

        std::thread::sleep(Duration::from_millis(interval_ms));
    }
}

// ─── Database thread ──────────────────────────────────────────────────────────

fn db_thread(
    db_path: String,
    rx: std::sync::mpsc::Receiver<DbMessage>,
    state: Arc<Mutex<AppState>>,
) {
    log::info!("DB thread started  (path: {})", db_path);

    let db = match Database::open(&db_path) {
        Ok(d) => d,
        Err(e) => {
            log::error!("Failed to open database '{db_path}': {e}");
            if let Ok(mut s) = state.lock() {
                s.status = format!("DB ERROR: {e}");
            }
            return;
        }
    };

    // Prune stale records on start-up (keep last 10 000 entries).
    let _ = db.prune_old_logs(10_000);

    // Refresh DB count in shared state.
    if let Ok(count) = db.snapshot_count() {
        if let Ok(mut s) = state.lock() {
            s.db_snapshot_count = count;
        }
    }

    for msg in rx {
        match msg {
            DbMessage::Snapshot(snap) => {
                if let Err(e) = db.insert_snapshot(&snap, 20) {
                    log::error!("DB insert_snapshot: {e}");
                }
            }
            DbMessage::Alert(alert) => {
                if let Err(e) = db.insert_alert(&alert) {
                    log::error!("DB insert_alert: {e}");
                }
            }
            DbMessage::IncrSnapshotCount => {
                if let Ok(count) = db.snapshot_count() {
                    if let Ok(mut s) = state.lock() {
                        s.db_snapshot_count = count;
                    }
                }
            }
        }
    }

    log::info!("DB thread exiting.");
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    // Initialise logger (RUST_LOG=info by default).
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("Starting System Resource & Risk Analyzer");

    let config = AppConfig::default();
    let db_path = config.database_path.clone();

    // Shared state between GUI and monitor threads.
    let app_state = Arc::new(Mutex::new(AppState::new(config)));

    // Bounded channel so a slow DB thread doesn't leak memory.
    let (db_tx, db_rx) = std::sync::mpsc::sync_channel::<DbMessage>(64);

    // ── Spawn monitor thread ──────────────────────────────────────────────────
    {
        let state_clone = Arc::clone(&app_state);
        let tx_clone = db_tx.clone();
        std::thread::Builder::new()
            .name("monitor".to_string())
            .spawn(move || monitor_thread(state_clone, tx_clone))
            .expect("Failed to spawn monitor thread");
    }

    // ── Spawn DB thread ───────────────────────────────────────────────────────
    {
        let state_clone = Arc::clone(&app_state);
        std::thread::Builder::new()
            .name("database".to_string())
            .spawn(move || db_thread(db_path, db_rx, state_clone))
            .expect("Failed to spawn database thread");
    }

    // ── Run GUI on main thread ────────────────────────────────────────────────
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("System Resource & Risk Analyzer"),
        ..Default::default()
    };

    eframe::run_native(
        "System Resource & Risk Analyzer",
        options,
        Box::new(move |cc| Ok(Box::new(gui::MonitorApp::new(cc, Arc::clone(&app_state))))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {e}"))?;

    Ok(())
}

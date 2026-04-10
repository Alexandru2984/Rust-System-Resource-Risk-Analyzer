//! Entry point for the System Resource & Risk Analyzer.
//!
//! ## Thread architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │  main thread                                                │
//! │  eframe::run_native() – GUI render loop (egui)             │
//! │  reads latest snapshot lock-free via ArcSwapOption          │
//! │  reads/writes UI state via Arc<Mutex<AppState>>             │
//! └───────────────────────────┬──────────────────────────────────┘
//!                             │ Arc<SharedState>
//! ┌───────────────────────────▼──────────────────────────────────┐
//! │  monitor_thread                                              │
//! │  SystemMonitor::collect_snapshot() every N ms               │
//! │  RiskAnalyzer::analyse(..., interval_ms)                    │
//! │  stores latest snapshot in ArcSwapOption                    │
//! │  updates UI state + sends DbMessage to db_thread            │
//! └───────────────────────────┬──────────────────────────────────┘
//!                             │ bounded mpsc channel
//! ┌───────────────────────────▼──────────────────────────────────┐
//! │  db_thread                                                   │
//! │  owns rusqlite::Connection (not Send – lives in this thread)│
//! │  Database::insert_snapshot() / insert_alert()               │
//! │  performs pruning + WAL checkpoint on clean shutdown        │
//! └──────────────────────────────────────────────────────────────┘
//! ```

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod database;
mod gui;
mod models;
mod monitor;
mod risk;

use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, Ordering as AtomicOrdering},
    mpsc, Arc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Result;

use config::AppConfig;
use database::Database;
use models::{RiskAlert, SnapshotForDb, SystemSnapshot};
use monitor::SystemMonitor;
use risk::RiskAnalyzer;

// ─── Shared application state ────────────────────────────────────────────────

/// Mutable UI-oriented state shared between the GUI and monitor thread.
///
/// The heavyweight `latest_snapshot` has been moved out into `SharedState` as
/// an `ArcSwapOption<SystemSnapshot>` so the GUI can read it lock-free.
pub struct AppState {
    /// Ring-buffer of per-sample global CPU usage (%) for the history graph.
    pub cpu_history: VecDeque<f32>,
    /// Ring-buffer of per-sample RAM usage (%) for the history graph.
    pub mem_history: VecDeque<f32>,
    /// Ring-buffer of aggregate network RX bytes per refresh interval.
    pub net_rx_history: VecDeque<f64>,
    /// Ring-buffer of aggregate network TX bytes per refresh interval.
    pub net_tx_history: VecDeque<f64>,
    /// Alerts currently visible in memory.
    pub alerts: Vec<RiskAlert>,
    /// Runtime-editable configuration.
    pub config: AppConfig,
    /// Total snapshots currently stored in the database.
    pub db_snapshot_count: i64,
    /// Short status string shown in the GUI title bar.
    pub status: String,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let max = config.max_history_points;
        Self {
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

    /// Integrate a new snapshot and any resulting alerts into the UI state.
    ///
    /// The full snapshot itself is stored separately in `SharedState.latest_snapshot`
    /// to allow lock-free reads from the GUI.
    pub fn ingest(&mut self, snapshot: &SystemSnapshot, new_alerts: Vec<RiskAlert>) {
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

        self.status = format!("Running  –  {} snapshots in DB", self.db_snapshot_count);
    }
}

/// Split shared state:
/// - `latest_snapshot`: lock-free current snapshot for GUI reads
/// - `ui`: mutable UI/config/history state protected by a mutex
pub struct SharedState {
    pub latest_snapshot: ArcSwapOption<SystemSnapshot>,
    pub ui: Mutex<AppState>,
}

impl SharedState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            latest_snapshot: ArcSwapOption::from(None),
            ui: Mutex::new(AppState::new(config)),
        }
    }
}

fn push_capped<T>(dq: &mut VecDeque<T>, value: T, max: usize) {
    if dq.len() >= max {
        dq.pop_front();
    }
    dq.push_back(value);
}

// ─── DB message transport ────────────────────────────────────────────────────

enum DbMessage {
    Snapshot(SnapshotForDb),
    Alert(RiskAlert),
    RefreshSnapshotCount,
}

// ─── Snapshot conversion ─────────────────────────────────────────────────────

fn make_db_snapshot(snapshot: &SystemSnapshot, top_n: usize) -> SnapshotForDb {
    let net_rx_bytes = snapshot.network.iter().map(|n| n.bytes_received).sum();
    let net_tx_bytes = snapshot.network.iter().map(|n| n.bytes_transmitted).sum();

    let mut top_processes = snapshot.processes.clone();
    top_processes.sort_by(|a, b| {
        b.cpu_usage_percent
            .partial_cmp(&a.cpu_usage_percent)
            .unwrap_or(Ordering::Equal)
    });
    top_processes.truncate(top_n);

    SnapshotForDb {
        timestamp: snapshot.timestamp,
        cpu_usage: snapshot.cpu.global_usage_percent,
        memory: snapshot.memory.clone(),
        net_rx_bytes,
        net_tx_bytes,
        top_processes,
    }
}

// ─── Monitor thread ──────────────────────────────────────────────────────────

fn monitor_thread(
    state: Arc<SharedState>,
    db_tx: mpsc::SyncSender<DbMessage>,
    shutdown: Arc<AtomicBool>,
) {
    log::info!("Monitor thread started (OS: {})", monitor::platform_info());

    let initial_thresholds = { state.ui.lock().config.thresholds.clone() };

    let mut sys_monitor = SystemMonitor::new();
    let mut risk_analyzer = RiskAnalyzer::new(initial_thresholds);
    let mut last_db_write = Instant::now() - Duration::from_secs(999);

    while !shutdown.load(AtomicOrdering::Relaxed) {
        let (interval_ms, db_interval_secs, thresholds) = {
            let s = state.ui.lock();
            (
                s.config.monitoring_interval_ms,
                s.config.db_log_interval_secs,
                s.config.thresholds.clone(),
            )
        };

        risk_analyzer.update_thresholds(thresholds);

        match sys_monitor.collect_snapshot() {
            Ok(snapshot) => {
                let new_alerts = risk_analyzer.analyse(&snapshot, interval_ms);

                // Store latest snapshot lock-free for GUI readers.
                state
                    .latest_snapshot
                    .store(Some(Arc::new(snapshot.clone())));

                if last_db_write.elapsed().as_secs() >= db_interval_secs {
                    let db_snapshot = make_db_snapshot(&snapshot, 20);

                    if let Err(err) = db_tx.try_send(DbMessage::Snapshot(db_snapshot)) {
                        log::warn!(
                            "Dropping DB snapshot because channel is full/disconnected: {err}"
                        );
                    }
                    if let Err(err) = db_tx.try_send(DbMessage::RefreshSnapshotCount) {
                        log::warn!("Dropping DB refresh-count message: {err}");
                    }

                    last_db_write = Instant::now();
                }

                for alert in &new_alerts {
                    if let Err(err) = db_tx.try_send(DbMessage::Alert(alert.clone())) {
                        log::warn!("Dropping DB alert because channel is full/disconnected: {err}");
                    }
                }

                let mut s = state.ui.lock();
                s.ingest(&snapshot, new_alerts);
            }
            Err(e) => {
                log::error!("Snapshot collection failed: {e}");
                let mut s = state.ui.lock();
                s.status = format!("ERROR: {e}");
            }
        }

        let sleep_ms = interval_ms.max(100);
        std::thread::sleep(Duration::from_millis(sleep_ms));
    }

    log::info!("Monitor thread exiting.");
}

// ─── Database thread ─────────────────────────────────────────────────────────

fn db_thread(
    db_path: String,
    rx: mpsc::Receiver<DbMessage>,
    state: Arc<SharedState>,
    shutdown: Arc<AtomicBool>,
) {
    log::info!("DB thread started (path: {})", db_path);

    let mut db = match Database::open(&db_path) {
        Ok(d) => d,
        Err(e) => {
            log::error!("Failed to open database '{db_path}': {e}");
            let mut s = state.ui.lock();
            s.status = format!("DB ERROR: {e}");
            return;
        }
    };

    if let Err(e) = db.prune_old_logs(10_000) {
        log::error!("Initial log pruning failed: {e}");
    }
    if let Err(e) = db.prune_old_alerts(10_000) {
        log::error!("Initial alert pruning failed: {e}");
    }

    if let Ok(count) = db.snapshot_count() {
        let mut s = state.ui.lock();
        s.db_snapshot_count = count;
    }

    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(msg) => match msg {
                DbMessage::Snapshot(snapshot) => {
                    if let Err(e) = db.insert_snapshot(&snapshot) {
                        log::error!("DB insert_snapshot failed: {e}");
                    }
                }
                DbMessage::Alert(alert) => {
                    if let Err(e) = db.insert_alert(&alert) {
                        log::error!("DB insert_alert failed: {e}");
                    }
                }
                DbMessage::RefreshSnapshotCount => {
                    if let Ok(count) = db.snapshot_count() {
                        let mut s = state.ui.lock();
                        s.db_snapshot_count = count;
                    }
                }
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if shutdown.load(AtomicOrdering::Relaxed) {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    if let Err(e) = db.prune_old_logs(10_000) {
        log::error!("Final log pruning failed: {e}");
    }
    if let Err(e) = db.prune_old_alerts(10_000) {
        log::error!("Final alert pruning failed: {e}");
    }
    if let Err(e) = db.wal_checkpoint() {
        log::error!("WAL checkpoint failed: {e}");
    }

    log::info!("DB thread exiting.");
}

// ─── Thread bootstrap helpers ────────────────────────────────────────────────

fn spawn_monitor_thread(
    state: Arc<SharedState>,
    db_tx: mpsc::SyncSender<DbMessage>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("monitor".to_string())
        .spawn(move || monitor_thread(state, db_tx, shutdown))
        .expect("Failed to spawn monitor thread")
}

fn spawn_db_thread(
    db_path: String,
    rx: mpsc::Receiver<DbMessage>,
    state: Arc<SharedState>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("database".to_string())
        .spawn(move || db_thread(db_path, rx, state, shutdown))
        .expect("Failed to spawn database thread")
}

// ─── main ────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("Starting System Resource & Risk Analyzer");

    let config_path = "system_analyzer.toml";
    let config = AppConfig::load(config_path)?;
    let db_path = config.database_path.clone();

    let shared_state = Arc::new(SharedState::new(config));
    let shutdown = Arc::new(AtomicBool::new(false));

    let (db_tx, db_rx) = mpsc::sync_channel::<DbMessage>(64);

    let monitor_handle = spawn_monitor_thread(
        Arc::clone(&shared_state),
        db_tx.clone(),
        Arc::clone(&shutdown),
    );

    let db_handle = spawn_db_thread(
        db_path,
        db_rx,
        Arc::clone(&shared_state),
        Arc::clone(&shutdown),
    );

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("System Resource & Risk Analyzer"),
        ..Default::default()
    };

    let gui_state = Arc::clone(&shared_state);
    let gui_result = eframe::run_native(
        "System Resource & Risk Analyzer",
        options,
        Box::new(move |cc| Ok(Box::new(gui::MonitorApp::new(cc, Arc::clone(&gui_state))))),
    );

    shutdown.store(true, AtomicOrdering::Relaxed);
    drop(db_tx);

    if let Err(e) = monitor_handle.join() {
        log::error!("Monitor thread join failed: {:?}", e);
    }
    if let Err(e) = db_handle.join() {
        log::error!("DB thread join failed: {:?}", e);
    }

    // Save config after all worker threads have exited.
    let state = shared_state.ui.lock();
    if let Err(e) = state.config.save() {
        log::error!("Failed to save config: {e}");
    }

    gui_result.map_err(|e| anyhow::anyhow!("GUI error: {e}"))?;

    Ok(())
}

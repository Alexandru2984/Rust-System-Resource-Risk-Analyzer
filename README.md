# 🖥 Rust System Resource & Risk Analyzer

A performant, cross-platform desktop application written in **Rust** that monitors system
resources in real time and automatically detects security risks and instability patterns.
Built with [`egui`](https://github.com/emilk/egui) for the GUI, [`sysinfo`](https://github.com/GuillaumeGomez/sysinfo) for metrics collection,
and [`rusqlite`](https://github.com/rusqlite/rusqlite) for chronological logging.

---

## ✨ Features

| Category | Details |
|---|---|
| **OS Detection** | Automatic detection of Windows, Linux, macOS at compile time and runtime |
| **CPU Monitoring** | Global usage %, per-core bars, frequency (MHz), CPU brand |
| **Memory Monitoring** | RAM used/total with %, Swap used/total with % |
| **Disk Monitoring** | Per-mount usage bars, total/available GB, filesystem type |
| **Network Monitoring** | Per-interface RX/TX bytes per refresh, cumulative totals |
| **Temperature Sensors** | Hardware component readings via sysinfo (where supported) |
| **Real-time Graphs** | 2-minute ring-buffer history plots for CPU, RAM, and network |
| **Process Table** | Searchable, sortable (PID / Name / CPU / Memory), risk-colour-coded |
| **Risk Alerts** | Automatic detection of high CPU/RAM, memory leaks, critical temps, suspicious processes |
| **Deduplication** | Alerts are deduplicated within a 60-second window per (category, subject) pair |
| **Persistent Logging** | Snapshots and alerts stored in SQLite with configurable flush intervals |
| **Settings Panel** | All thresholds and intervals are editable at runtime without restart |

---

## 🖼 Interface

```
┌──────────────────────────────────────────────────────────────────────┐
│ 🖥 System Analyzer  │  Linux  │  22:14:05  │  Running – 42 snapshots │
├──────────────────────────────────────────────────────────────────────┤
│  📊 Dashboard  │  ⚙ Processes  │  ⚠ Alerts (3)  │  🔧 Settings      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─ CPU Usage ──┐  ┌─ RAM Usage ──┐  ┌─ Swap ──────┐               │
│  │  ████░░  42% │  │  ██████  77% │  │  █░░░░  12% │               │
│  └─────────────┘  └─────────────┘  └─────────────┘               │
│                                                                      │
│  ┌─ CPU History (%) ────────────┐  ┌─ Memory History (%) ──────────┐│
│  │  100 ┤                       │  │  100 ┤                         ││
│  │      │    ╭╮  ╭─╮            │  │      │  ╭────────────────      ││
│  │    0 ┤────╯╰──╯ ╰────────    │  │    0 ┤──╯                      ││
│  └──────────────────────────────┘  └────────────────────────────────┘│
│                                                                      │
│  ┌─ Network (bytes/refresh) ────┐  ┌─ Disk Usage ───────────────────┐│
│  │  RX ──  TX ──                │  │  / (sda1)  ████████░  87%      ││
│  │   ╭╮                         │  │  /home     █████░░░░  58%      ││
│  └──────────────────────────────┘  └────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🏗 Architecture

The application uses **three dedicated threads** that communicate through shared state and
channels, keeping the GUI always responsive:

```
┌──────────────────────────────────────────────────────────────────────┐
│  main thread                                                          │
│  eframe::run_native()  ─  egui render loop (~60 fps)                 │
│  Reads AppState via Arc<Mutex<AppState>>   (try_lock per frame)       │
└───────────────────────────────┬──────────────────────────────────────┘
                                │  Arc<Mutex<AppState>>
┌───────────────────────────────▼──────────────────────────────────────┐
│  monitor thread                                                       │
│  SystemMonitor::collect_snapshot()   every N ms (default 2 000 ms)   │
│  RiskAnalyzer::analyse()  →  push alerts + snapshot into AppState     │
│  Forward DbMessage to db thread via bounded mpsc channel (cap 64)     │
└───────────────────────────────┬──────────────────────────────────────┘
                                │  mpsc::SyncSender<DbMessage>
┌───────────────────────────────▼──────────────────────────────────────┐
│  database thread                                                      │
│  Owns rusqlite::Connection (not Send – lives entirely in this thread) │
│  insert_snapshot()  /  insert_alert()   on each DbMessage             │
│  Prunes old rows on startup (keeps last 10 000 entries)               │
└──────────────────────────────────────────────────────────────────────┘
```

### Module layout

```
src/
├── main.rs        Entry point, AppState, thread orchestration
├── models.rs      All shared data structures (Snapshot, Alert, Metrics…)
├── config.rs      AppConfig + AlertThresholds with Default impl
├── errors.rs      Centralised AppError (thiserror) + AppResult alias
├── monitor.rs     SystemMonitor wrapping sysinfo; detect_os()
├── database.rs    Database struct – SQLite schema + CRUD helpers
├── risk.rs        RiskAnalyzer – six detection algorithms
└── gui.rs         MonitorApp (eframe::App) – four panels
```

---

## 🔍 Risk Detection Algorithms

| Algorithm | Trigger |
|---|---|
| **High Global CPU** | `global_cpu_usage ≥ cpu_warning_percent` |
| **High Global Memory** | `ram_used% ≥ memory_warning_percent` |
| **High CPU Process** | `process.cpu_usage ≥ process_cpu_warning_percent` |
| **High Memory Process** | `process.rss_mb ≥ process_memory_warning_mb` |
| **Memory Leak** | Last N consecutive samples for a PID are strictly increasing |
| **Critical Temperature** | `sensor_temp ≥ min(hw_critical, config_critical)` |
| **Disk Space Low** | `mount_used% ≥ disk_warning_percent` |
| **Unusual Network** | `bytes_per_refresh / interval_secs ≥ threshold` |
| **Suspicious Process** | Name contains any of 18 known-malicious patterns (xmrig, mimikatz, netcat…) |

All algorithms include a **60-second deduplication window** per `(category, subject)` pair
to avoid alert floods.

---

## 🗄 Database Schema

```sql
-- Periodic system snapshots
CREATE TABLE system_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,   -- RFC-3339
    cpu_usage       REAL    NOT NULL,   -- 0–100
    memory_used_kb  INTEGER NOT NULL,
    memory_total_kb INTEGER NOT NULL,
    swap_used_kb    INTEGER NOT NULL,
    swap_total_kb   INTEGER NOT NULL,
    net_rx_bytes    INTEGER NOT NULL,   -- aggregate delta across all interfaces
    net_tx_bytes    INTEGER NOT NULL
);

-- Top-20 processes per snapshot (by CPU usage)
CREATE TABLE process_snapshots (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id    INTEGER NOT NULL REFERENCES system_logs(id) ON DELETE CASCADE,
    pid       INTEGER NOT NULL,
    name      TEXT    NOT NULL,
    cpu_usage REAL    NOT NULL,
    memory_kb INTEGER NOT NULL
);

-- Risk alerts from the detection engine
CREATE TABLE risk_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    risk_level   TEXT    NOT NULL,  -- "Info" | "Low" | "Medium" | "High" | "Critical"
    category     TEXT    NOT NULL,
    description  TEXT    NOT NULL,
    process_pid  INTEGER,
    process_name TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
```

The database is created automatically in the working directory as `system_monitor.db`.
WAL journal mode is enabled for better concurrent read performance.

---

## 🚀 Getting Started

### Prerequisites

| Requirement | Notes |
|---|---|
| **Rust** ≥ 1.75 | Install via [rustup.rs](https://rustup.rs) |
| **Linux** | `libx11-dev`, `libxcb-*`, `libwayland-dev`, `pkg-config` (see below) |
| **Windows** | MSVC toolchain recommended; no extra deps needed |
| **macOS** | Xcode Command Line Tools |

#### Linux system packages (Debian/Ubuntu)

```bash
sudo apt install -y \
    libx11-dev libxcb1-dev libxcb-render0-dev libxcb-shape0-dev \
    libxcb-xfixes0-dev libwayland-dev libxkbcommon-dev \
    pkg-config build-essential
```

### Build & Run

```bash
# Clone the repository
git clone https://github.com/youruser/rust-system-analyzer.git
cd rust-system-analyzer

# Debug build (fast compile, larger binary)
cargo run

# Release build (optimised, LTO, stripped – ~5 MB)
cargo build --release
./target/release/rust-system-analyzer
```

### Logging

The application uses `env_logger`. Set the `RUST_LOG` environment variable to control
verbosity:

```bash
RUST_LOG=debug   cargo run    # verbose – all sysinfo refreshes
RUST_LOG=info    cargo run    # default – alerts + DB events
RUST_LOG=warn    cargo run    # alerts only
RUST_LOG=error   cargo run    # silent unless something breaks
```

---

## ⚙ Configuration

All thresholds and intervals can be changed **at runtime** from the **Settings** panel
without restarting the application. Changes take effect on the next monitoring cycle.

| Setting | Default | Description |
|---|---|---|
| `monitoring_interval_ms` | `2 000` | How often metrics are collected |
| `db_log_interval_secs` | `30` | How often snapshots are written to SQLite |
| `max_history_points` | `60` | Graph ring-buffer depth (60 × 2 s = 2 min) |
| `max_alerts` | `500` | Maximum alerts kept in memory |
| `cpu_warning_percent` | `75` | Global CPU warning threshold |
| `cpu_critical_percent` | `90` | Global CPU critical threshold |
| `memory_warning_percent` | `75` | RAM warning threshold |
| `memory_critical_percent` | `90` | RAM critical threshold |
| `disk_warning_percent` | `85` | Disk usage warning threshold |
| `disk_critical_percent` | `95` | Disk usage critical threshold |
| `temp_warning_celsius` | `80` | Temperature warning threshold |
| `temp_critical_celsius` | `95` | Temperature critical threshold |
| `process_cpu_warning_percent` | `50` | Per-process CPU threshold |
| `process_memory_warning_mb` | `1 024` | Per-process RAM threshold (MB) |
| `memory_leak_samples` | `5` | Consecutive growing samples to flag a leak |
| `network_bytes_per_sec_threshold` | `100 MB/s` | Per-interface network alert |

---

## 📦 Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `sysinfo` | 0.31 | Cross-platform system metrics (CPU, RAM, processes, disks, net, temps) |
| `eframe` | 0.28 | Native window + event loop (wraps egui) |
| `egui` | 0.28 | Immediate-mode GUI |
| `egui_plot` | 0.28 | Real-time line graphs |
| `egui_extras` | 0.28 | Sortable `TableBuilder` for the process list |
| `rusqlite` | 0.31 | SQLite bindings (`bundled` feature – no system SQLite needed) |
| `anyhow` | 1.0 | Ergonomic error propagation |
| `thiserror` | 1.0 | Derive-based typed errors |
| `serde` + `serde_json` | 1.0 | Serialisation for DB fields |
| `chrono` | 0.4 | Timestamps |
| `log` + `env_logger` | 0.4 / 0.11 | Structured logging |

> **SQLite portability:** `rusqlite` is compiled with the `bundled` feature, so no system
> SQLite installation is required. Switching to PostgreSQL requires only replacing the
> `database.rs` layer with `sqlx` + a `postgres` feature flag.

---

## 🔒 Security Notes

- The application reads system metrics using standard OS APIs and requires **no elevated
  privileges** on Linux/macOS for basic operation.
- Temperature sensor access may require the `lm-sensors` kernel modules to be loaded on Linux.
- The suspicious-process detection is heuristic (name-pattern matching) and is **not** a
  substitute for a real endpoint-detection solution.
- The SQLite database is stored unencrypted; do not store this file in a publicly readable
  location.

---

## 🗺 Roadmap

- [ ] Persist and restore `AppConfig` to/from a TOML file
- [ ] PostgreSQL backend via `sqlx`
- [ ] Export alerts to CSV / JSON
- [ ] Desktop notifications (OS toast) for Critical alerts
- [ ] Process kill button from the Processes panel
- [ ] Plugin system for custom risk rules
- [ ] Docker / systemd service mode (headless, metrics-only)

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.
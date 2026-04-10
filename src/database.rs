//! Persistence layer – SQLite via `rusqlite` (bundled build).
//!
//! All writes go through a dedicated database thread that owns the
//! `Connection` exclusively, so there are no Send/Sync concerns.
//!
//! ## Guarantees
//! - `PRAGMA foreign_keys = ON` is enabled, so `ON DELETE CASCADE` works.
//! - Snapshot writes are wrapped in a single transaction.
//! - Alert rows are stored with plain labels, not JSON-quoted strings.
//! - Old logs and alerts can be pruned independently.
//! - A clean shutdown can checkpoint the WAL back into the main DB file.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use crate::models::{RiskAlert, SnapshotForDb};

// ─── Schema DDL ──────────────────────────────────────────────────────────────

const SCHEMA_SQL: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS system_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    cpu_usage       REAL    NOT NULL,
    memory_used_kb  INTEGER NOT NULL,
    memory_total_kb INTEGER NOT NULL,
    swap_used_kb    INTEGER NOT NULL,
    swap_total_kb   INTEGER NOT NULL,
    net_rx_bytes    INTEGER NOT NULL,
    net_tx_bytes    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS process_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id      INTEGER NOT NULL REFERENCES system_logs(id) ON DELETE CASCADE,
    pid         INTEGER NOT NULL,
    name        TEXT    NOT NULL,
    cpu_usage   REAL    NOT NULL,
    memory_kb   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    risk_level   TEXT    NOT NULL,
    category     TEXT    NOT NULL,
    description  TEXT    NOT NULL,
    process_pid  INTEGER,
    process_name TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_system_logs_ts    ON system_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_risk_alerts_ts    ON risk_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_risk_alerts_level ON risk_alerts(risk_level);
";

// ─── Database Handle ─────────────────────────────────────────────────────────

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create the SQLite database at `path` and apply the schema.
    pub fn open(path: &str) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("Cannot open database at '{path}'"))?;

        conn.execute_batch(SCHEMA_SQL)
            .context("Failed to apply database schema")?;

        log::info!("Database opened at '{path}'");
        Ok(Self { conn })
    }

    // ── Snapshot insert ──────────────────────────────────────────────────────

    /// Persist a lightweight DB snapshot in a single transaction.
    ///
    /// `SnapshotForDb.top_processes` is expected to already be sorted/truncated
    /// by the caller, so this method simply inserts what it receives.
    pub fn insert_snapshot(&mut self, snapshot: &SnapshotForDb) -> Result<i64> {
        let tx = self
            .conn
            .transaction()
            .context("insert_snapshot: begin transaction failed")?;

        tx.execute(
            "INSERT INTO system_logs
                 (timestamp, cpu_usage, memory_used_kb, memory_total_kb,
                  swap_used_kb, swap_total_kb, net_rx_bytes, net_tx_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                snapshot.timestamp.to_rfc3339(),
                snapshot.cpu_usage as f64,
                snapshot.memory.used_bytes as i64 / 1024,
                snapshot.memory.total_bytes as i64 / 1024,
                snapshot.memory.swap_used_bytes as i64 / 1024,
                snapshot.memory.swap_total_bytes as i64 / 1024,
                snapshot.net_rx_bytes as i64,
                snapshot.net_tx_bytes as i64,
            ],
        )
        .context("insert_snapshot: system_logs INSERT failed")?;

        let log_id = tx.last_insert_rowid();

        for proc in &snapshot.top_processes {
            tx.execute(
                "INSERT INTO process_snapshots
                     (log_id, pid, name, cpu_usage, memory_kb)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    log_id,
                    proc.pid as i64,
                    &proc.name,
                    proc.cpu_usage_percent as f64,
                    proc.memory_bytes as i64 / 1024,
                ],
            )
            .context("insert_snapshot: process_snapshots INSERT failed")?;
        }

        tx.commit()
            .context("insert_snapshot: transaction commit failed")?;

        log::debug!(
            "Snapshot logged (log_id={log_id}, processes={})",
            snapshot.top_processes.len()
        );
        Ok(log_id)
    }

    // ── Alert insert ─────────────────────────────────────────────────────────

    /// Persist a `RiskAlert` using plain text labels.
    pub fn insert_alert(&self, alert: &RiskAlert) -> Result<i64> {
        self.conn
            .execute(
                "INSERT INTO risk_alerts
                     (timestamp, risk_level, category, description, process_pid, process_name, acknowledged)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    alert.timestamp.to_rfc3339(),
                    alert.risk_level.label(),
                    alert.category.label(),
                    &alert.description,
                    alert.process_pid.map(|p| p as i64),
                    alert.process_name.as_deref(),
                    i32::from(alert.acknowledged),
                ],
            )
            .context("insert_alert: risk_alerts INSERT failed")?;

        let id = self.conn.last_insert_rowid();
        log::debug!(
            "Alert persisted (db_id={id}, level={}, category={})",
            alert.risk_level.label(),
            alert.category.label()
        );
        Ok(id)
    }

    // ── Alert ack ────────────────────────────────────────────────────────────

    #[allow(dead_code)]
    pub fn acknowledge_alert(&self, db_id: i64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE risk_alerts SET acknowledged = 1 WHERE id = ?1",
                params![db_id],
            )
            .context("acknowledge_alert failed")?;
        Ok(())
    }

    // ── Counts / queries ─────────────────────────────────────────────────────

    pub fn snapshot_count(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM system_logs", [], |r| r.get(0))
            .context("snapshot_count query failed")?;
        Ok(count)
    }

    #[allow(dead_code)]
    pub fn alert_count(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM risk_alerts", [], |r| r.get(0))
            .context("alert_count query failed")?;
        Ok(count)
    }

    #[allow(dead_code)]
    pub fn recent_logs(&self, n: usize) -> Result<Vec<(String, f64, i64, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, cpu_usage, memory_used_kb, memory_total_kb
             FROM system_logs
             ORDER BY id DESC
             LIMIT ?1",
        )?;

        let rows = stmt
            .query_map(params![n as i64], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, f64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("recent_logs query failed")?;

        Ok(rows)
    }

    // ── Pruning ──────────────────────────────────────────────────────────────

    /// Keep only the newest `keep` rows from `system_logs`.
    ///
    /// Because foreign keys are ON and `process_snapshots.log_id` has
    /// `ON DELETE CASCADE`, child rows are deleted automatically.
    pub fn prune_old_logs(&self, keep: usize) -> Result<usize> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM system_logs
                 WHERE id NOT IN (
                     SELECT id FROM system_logs ORDER BY id DESC LIMIT ?1
                 )",
                params![keep as i64],
            )
            .context("prune_old_logs failed")?;

        if deleted > 0 {
            log::info!("Pruned {deleted} old log entries from database");
        }

        Ok(deleted)
    }

    /// Keep only the newest `keep` rows from `risk_alerts`.
    pub fn prune_old_alerts(&self, keep: usize) -> Result<usize> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM risk_alerts
                 WHERE id NOT IN (
                     SELECT id FROM risk_alerts ORDER BY id DESC LIMIT ?1
                 )",
                params![keep as i64],
            )
            .context("prune_old_alerts failed")?;

        if deleted > 0 {
            log::info!("Pruned {deleted} old alert entries from database");
        }

        Ok(deleted)
    }

    // ── WAL maintenance ──────────────────────────────────────────────────────

    /// Perform a WAL checkpoint and truncate the WAL file.
    ///
    /// Useful during graceful shutdown so the `.db-wal` file does not keep
    /// growing unnecessarily.
    pub fn wal_checkpoint(&self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .context("wal_checkpoint failed")?;
        Ok(())
    }
}

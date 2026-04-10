//! Immediate-mode GUI built with egui / eframe 0.28.
//!
//! Panels:
//!  - **Dashboard**  – live gauges, ring-buffer plots, disk/temperature/network summary
//!  - **Processes**  – searchable & sortable process table, risk-colour-coded rows
//!  - **Alerts**     – filterable alert feed with acknowledge support
//!  - **Settings**   – runtime-editable thresholds and intervals
//!
//! The GUI owns an `Arc<SharedState>` that it shares with the background
//! monitor thread.  The latest snapshot is read lock-free via `ArcSwapOption`,
//! while mutable UI state is guarded by a lightweight `parking_lot::Mutex`.

use std::collections::VecDeque;
use std::sync::Arc;

use eframe::egui::{self, Color32, RichText, ScrollArea, Ui};
use egui_extras::{Column, TableBuilder};
use egui_plot::{Line, Plot, PlotPoints};

use crate::models::{RiskAlert, RiskLevel, SystemSnapshot};
use crate::{AppState, SharedState};

// ─── Tabs ────────────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Dashboard,
    Processes,
    Alerts,
    Settings,
}

// ─── Process table sort state ────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum ProcSort {
    Pid,
    Name,
    Cpu,
    Memory,
}

// ─── MonitorApp ──────────────────────────────────────────────────────────────

pub struct MonitorApp {
    state: Arc<SharedState>,
    tab: Tab,
    proc_filter: String,
    proc_sort: ProcSort,
    proc_sort_asc: bool,
    alert_min_level: Option<RiskLevel>,
    show_acked: bool,
}

impl MonitorApp {
    pub fn new(cc: &eframe::CreationContext<'_>, state: Arc<SharedState>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Self {
            state,
            tab: Tab::Dashboard,
            proc_filter: String::new(),
            proc_sort: ProcSort::Cpu,
            proc_sort_asc: false,
            alert_min_level: None,
            show_acked: false,
        }
    }
}

impl eframe::App for MonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Repaint every 500 ms so graphs stay live without pegging the CPU.
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        let latest_snapshot = self.state.latest_snapshot.load_full();
        let mut state = match self.state.ui.try_lock() {
            Some(s) => s,
            None => return, // skip frame – monitor thread holds the lock
        };

        // ── Top navigation bar ────────────────────────────────────────────────
        egui::TopBottomPanel::top("nav").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🖥  System Analyzer");
                ui.separator();

                let os = crate::monitor::detect_os();
                let now = chrono::Local::now().format("%H:%M:%S");
                ui.label(RichText::new(format!("{os}  │  {now}")).small());

                if !state.status.is_empty() {
                    ui.separator();
                    let color = if state.status.starts_with("ERROR") {
                        Color32::RED
                    } else {
                        Color32::from_rgb(100, 220, 100)
                    };
                    ui.label(RichText::new(&state.status).small().color(color));
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!(
                            "DB snapshots: {}  │  alerts: {}",
                            state.db_snapshot_count,
                            state.alerts.len()
                        ))
                        .small()
                        .weak(),
                    );
                });
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Dashboard, "📊 Dashboard");
                ui.selectable_value(&mut self.tab, Tab::Processes, "⚙ Processes");
                let alert_count = state.alerts.iter().filter(|a| !a.acknowledged).count();
                let alert_label = if alert_count > 0 {
                    format!("⚠ Alerts ({})", alert_count)
                } else {
                    "⚠ Alerts".to_string()
                };
                ui.selectable_value(&mut self.tab, Tab::Alerts, alert_label);
                ui.selectable_value(&mut self.tab, Tab::Settings, "🔧 Settings");
            });
        });

        // ── Alert badge in status bar ─────────────────────────────────────────
        let critical_count = state
            .alerts
            .iter()
            .filter(|a| !a.acknowledged && a.risk_level == RiskLevel::Critical)
            .count();
        if critical_count > 0 {
            egui::TopBottomPanel::bottom("alert_bar").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("🚨  {} CRITICAL alert(s) active!", critical_count))
                            .color(Color32::from_rgb(220, 20, 60))
                            .strong(),
                    );
                });
            });
        }

        // ── Central panel ─────────────────────────────────────────────────────
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Dashboard => show_dashboard(ui, &state, latest_snapshot.as_deref()),
            Tab::Processes => {
                show_processes(
                    ui,
                    &state,
                    latest_snapshot.as_deref(),
                    &mut self.proc_filter,
                    &mut self.proc_sort,
                    &mut self.proc_sort_asc,
                );
            }
            Tab::Alerts => {
                show_alerts(
                    ui,
                    &mut state,
                    &mut self.alert_min_level,
                    &mut self.show_acked,
                );
            }
            Tab::Settings => show_settings(ui, &mut state),
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Dashboard
// ═══════════════════════════════════════════════════════════════════════════════

fn show_dashboard(ui: &mut Ui, state: &AppState, snap: Option<&SystemSnapshot>) {
    ScrollArea::vertical().show(ui, |ui| {
        let Some(snap) = snap else {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new("⏳  Collecting first snapshot…").heading());
            });
            return;
        };

        // ── System header ─────────────────────────────────────────────────────
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "🖥  {}  {}",
                    snap.os_info.name, snap.os_info.version
                ));
                ui.separator();
                ui.label(format!("🔧  Kernel: {}", snap.os_info.kernel));
                ui.separator();
                ui.label(format!("🌐  Host: {}", snap.os_info.hostname));
                ui.separator();
                ui.label(format!(
                    "⏱  Uptime: {}",
                    format_uptime(snap.os_info.uptime_secs)
                ));
                ui.separator();
                ui.label(format!(
                    "🧠  CPU: {} ({} cores @ {} MHz)",
                    snap.cpu.brand, snap.cpu.core_count, snap.cpu.frequency_mhz
                ));
            });
        });

        ui.add_space(6.0);

        // ── Summary gauges ────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            metric_card(
                ui,
                "CPU Usage",
                snap.cpu.global_usage_percent,
                cpu_color(snap.cpu.global_usage_percent),
            );
            metric_card(
                ui,
                "RAM Usage",
                snap.memory.used_percent(),
                mem_color(snap.memory.used_percent()),
            );
            metric_card(
                ui,
                "Swap Usage",
                snap.memory.swap_used_percent(),
                mem_color(snap.memory.swap_used_percent()),
            );
            if let Some(t) = snap.temperatures.first() {
                metric_card(
                    ui,
                    &format!("🌡 {}", t.component),
                    t.temperature_celsius.min(100.0),
                    temp_color(t.temperature_celsius),
                );
            }
        });

        ui.add_space(6.0);

        // ── History plots ─────────────────────────────────────────────────────
        ui.columns(2, |cols| {
            // CPU history
            cols[0].label(RichText::new("CPU History (%)").strong());
            egui::Frame::group(cols[0].style()).show(&mut cols[0], |ui| {
                history_plot(
                    ui,
                    "cpu_hist",
                    &state.cpu_history,
                    0.0,
                    100.0,
                    Color32::from_rgb(100, 200, 100),
                    "CPU %",
                );
            });

            // Memory history
            cols[1].label(RichText::new("Memory History (%)").strong());
            egui::Frame::group(cols[1].style()).show(&mut cols[1], |ui| {
                history_plot(
                    ui,
                    "mem_hist",
                    &state.mem_history,
                    0.0,
                    100.0,
                    Color32::from_rgb(100, 149, 237),
                    "RAM %",
                );
            });
        });

        ui.add_space(6.0);

        // ── Network + Disk ────────────────────────────────────────────────────
        ui.columns(2, |cols| {
            // Network
            cols[0].label(RichText::new("Network Traffic (bytes/refresh)").strong());
            egui::Frame::group(cols[0].style()).show(&mut cols[0], |ui| {
                let max_y = state
                    .net_rx_history
                    .iter()
                    .chain(state.net_tx_history.iter())
                    .cloned()
                    .fold(1.0_f64, f64::max);
                let rx_pts: PlotPoints = state
                    .net_rx_history
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| [i as f64, v])
                    .collect();
                let tx_pts: PlotPoints = state
                    .net_tx_history
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| [i as f64, v])
                    .collect();
                Plot::new("net_hist")
                    .height(140.0)
                    .include_y(0.0)
                    .include_y(max_y * 1.1)
                    .legend(egui_plot::Legend::default())
                    .show(ui, |pu| {
                        pu.line(
                            Line::new(rx_pts)
                                .color(Color32::from_rgb(100, 220, 100))
                                .name("RX"),
                        );
                        pu.line(
                            Line::new(tx_pts)
                                .color(Color32::from_rgb(220, 150, 50))
                                .name("TX"),
                        );
                    });
            });

            // Disk usage
            cols[1].label(RichText::new("Disk Usage").strong());
            egui::Frame::group(cols[1].style()).show(&mut cols[1], |ui| {
                ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                    for disk in &snap.disks {
                        let pct = disk.used_percent();
                        ui.label(format!("{} ({})", disk.mount_point, disk.name));
                        // Capture available_width() *before* building the widget –
                        // f32::INFINITY is not a valid desired_width in egui and
                        // triggers a placer assertion.
                        let bar_w = (ui.available_width() - 4.0).max(60.0);
                        ui.add(
                            egui::ProgressBar::new((pct / 100.0).clamp(0.0, 1.0))
                                .desired_width(bar_w)
                                .fill(disk_color(pct))
                                .text(format!(
                                    "{:.1}%  –  {:.1}/{:.1} GB",
                                    pct,
                                    disk.used_bytes() as f64 / 1e9,
                                    disk.total_bytes as f64 / 1e9,
                                )),
                        );
                        ui.add_space(2.0);
                    }
                });
            });
        });

        ui.add_space(6.0);

        // ── Per-core CPU ──────────────────────────────────────────────────────
        if !snap.cpu.per_core_usage.is_empty() {
            ui.label(RichText::new("Per-Core CPU Usage").strong());
            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::Grid::new("per_core_grid")
                    .num_columns(4)
                    .spacing([8.0, 4.0])
                    .show(ui, |ui| {
                        for (i, &usage) in snap.cpu.per_core_usage.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("C{i:>2}")).small().monospace());
                                ui.add(
                                    egui::ProgressBar::new((usage / 100.0).clamp(0.0, 1.0))
                                        .desired_width(90.0)
                                        .fill(cpu_color(usage))
                                        .text(format!("{:.0}%", usage)),
                                );
                            });
                            if (i + 1) % 4 == 0 {
                                ui.end_row();
                            }
                        }
                    });
            });
            ui.add_space(6.0);
        }

        // ── Temperature sensors ───────────────────────────────────────────────
        if !snap.temperatures.is_empty() {
            ui.label(RichText::new("Temperature Sensors").strong());
            egui::Frame::group(ui.style()).show(ui, |ui| {
                egui::Grid::new("temps_grid")
                    .striped(true)
                    .num_columns(4)
                    .spacing([20.0, 4.0])
                    .show(ui, |ui| {
                        ui.strong("Component");
                        ui.strong("Temp");
                        ui.strong("Max");
                        ui.strong("Critical");
                        ui.end_row();
                        for t in &snap.temperatures {
                            ui.label(&t.component);
                            ui.label(
                                RichText::new(format!("{:.1}°C", t.temperature_celsius))
                                    .color(temp_color(t.temperature_celsius)),
                            );
                            ui.label(format!("{:.1}°C", t.max_celsius));
                            ui.label(
                                t.critical_celsius
                                    .map(|c| format!("{:.1}°C", c))
                                    .unwrap_or_else(|| "–".to_string()),
                            );
                            ui.end_row();
                        }
                    });
            });
            ui.add_space(6.0);
        }

        // ── Recent alerts ─────────────────────────────────────────────────────
        let recent: Vec<&RiskAlert> = state
            .alerts
            .iter()
            .rev()
            .filter(|a| !a.acknowledged)
            .take(5)
            .collect();
        if !recent.is_empty() {
            ui.label(RichText::new("Recent Alerts (unacknowledged)").strong());
            egui::Frame::group(ui.style()).show(ui, |ui| {
                for a in recent {
                    alert_row(ui, a);
                }
            });
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Processes
// ═══════════════════════════════════════════════════════════════════════════════

fn show_processes(
    ui: &mut Ui,
    state: &AppState,
    snap: Option<&SystemSnapshot>,
    filter: &mut String,
    sort: &mut ProcSort,
    sort_asc: &mut bool,
) {
    let Some(snap) = snap else {
        ui.label("No data yet.");
        return;
    };

    // Search bar
    ui.horizontal(|ui| {
        ui.label("🔍 Filter:");
        ui.text_edit_singleline(filter);
        if ui.small_button("✖").clicked() {
            filter.clear();
        }
        ui.separator();
        ui.label(format!("{} processes", snap.processes.len()));
    });
    ui.add_space(4.0);

    // Sort logic
    let mut procs = snap.processes.clone();
    let filter_lower = filter.to_lowercase();
    if !filter_lower.is_empty() {
        procs.retain(|p| {
            p.name.to_lowercase().contains(&filter_lower)
                || p.pid.to_string().contains(&filter_lower)
        });
    }
    match sort {
        ProcSort::Pid => procs.sort_by_key(|p| p.pid),
        ProcSort::Name => procs.sort_by(|a, b| a.name.cmp(&b.name)),
        ProcSort::Cpu => procs.sort_by(|a, b| {
            // NaN-safe: sysinfo can return NaN on the first sample or for
            // zombie processes.  Treat NaN as equal to avoid a panic.
            b.cpu_usage_percent
                .partial_cmp(&a.cpu_usage_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        ProcSort::Memory => procs.sort_by_key(|p| std::cmp::Reverse(p.memory_bytes)),
    }
    if *sort_asc {
        procs.reverse();
    }

    // Build table
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .column(Column::auto().at_least(60.0))
        .column(Column::remainder().at_least(180.0))
        .column(Column::auto().at_least(70.0))
        .column(Column::auto().at_least(90.0))
        .column(Column::auto().at_least(80.0))
        .column(Column::auto().at_least(70.0))
        .header(22.0, |mut h| {
            sort_header(&mut h, "PID", ProcSort::Pid, sort, sort_asc);
            sort_header(&mut h, "Name", ProcSort::Name, sort, sort_asc);
            sort_header(&mut h, "CPU %", ProcSort::Cpu, sort, sort_asc);
            sort_header(&mut h, "Memory", ProcSort::Memory, sort, sort_asc);
            h.col(|ui| {
                ui.strong("Status");
            });
            h.col(|ui| {
                ui.strong("Risk");
            });
        })
        .body(|mut body| {
            for proc in &procs {
                let cpu = proc.cpu_usage_percent;
                let mem = proc.memory_bytes / (1024 * 1024);
                let risk = proc_risk_level(proc, &state.config.thresholds);
                let row_color = risk_row_color(&risk);

                body.row(20.0, |mut row| {
                    row.col(|ui| {
                        ui.label(RichText::new(proc.pid.to_string()).color(row_color));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&proc.name).color(row_color));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(format!("{cpu:.1}%")).color(cpu_color(cpu)));
                    });
                    row.col(|ui| {
                        ui.label(format!("{mem} MB"));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&proc.status).small());
                    });
                    row.col(|ui| {
                        risk_badge(ui, &risk);
                    });
                });
            }
        });
}

fn sort_header(
    header: &mut egui_extras::TableRow<'_, '_>,
    label: &str,
    col: ProcSort,
    current: &mut ProcSort,
    asc: &mut bool,
) {
    header.col(|ui| {
        let indicator = if *current == col {
            if *asc {
                " ↑"
            } else {
                " ↓"
            }
        } else {
            ""
        };
        if ui.button(format!("{label}{indicator}")).clicked() {
            if *current == col {
                *asc = !*asc;
            } else {
                *current = col;
                *asc = false;
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Alerts
// ═══════════════════════════════════════════════════════════════════════════════

fn show_alerts(
    ui: &mut Ui,
    state: &mut AppState,
    min_level: &mut Option<RiskLevel>,
    show_acked: &mut bool,
) {
    ui.horizontal(|ui| {
        ui.label("Filter level:");
        for level in &[
            RiskLevel::Info,
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let (r, g, b) = level.rgb();
            let active = min_level.as_ref() == Some(level);
            let btn =
                egui::Button::new(RichText::new(level.label()).color(Color32::from_rgb(r, g, b)));
            if ui.add(btn.selected(active)).clicked() {
                if active {
                    *min_level = None;
                } else {
                    *min_level = Some(level.clone());
                }
            }
        }
        ui.separator();
        ui.checkbox(show_acked, "Show acknowledged");
        ui.separator();

        let unacked = state.alerts.iter().filter(|a| !a.acknowledged).count();
        if ui
            .button(format!("✅ Acknowledge all ({unacked})"))
            .clicked()
        {
            for a in &mut state.alerts {
                a.acknowledged = true;
            }
        }
        if ui.button("🗑 Clear all").clicked() {
            state.alerts.clear();
        }
    });
    ui.separator();

    let alerts: Vec<usize> = state
        .alerts
        .iter()
        .enumerate()
        .filter(|(_, a)| {
            if !*show_acked && a.acknowledged {
                return false;
            }
            if let Some(min) = min_level {
                if a.risk_level < *min {
                    return false;
                }
            }
            true
        })
        .map(|(i, _)| i)
        .rev()
        .collect();

    ui.label(format!("{} alert(s) shown", alerts.len()));
    ui.separator();

    let mut to_ack: Option<usize> = None;

    ScrollArea::vertical().show(ui, |ui| {
        for &idx in &alerts {
            let alert = &state.alerts[idx];
            let (r, g, b) = alert.risk_level.rgb();
            egui::Frame::group(ui.style())
                .stroke(egui::Stroke::new(1.0, Color32::from_rgb(r, g, b)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("[{}]", alert.risk_level.label()))
                                .strong()
                                .color(Color32::from_rgb(r, g, b)),
                        );
                        ui.label(RichText::new(alert.category.icon()).heading());
                        ui.label(alert.category.label());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if !state.alerts[idx].acknowledged {
                                if ui.small_button("✅").on_hover_text("Acknowledge").clicked() {
                                    to_ack = Some(idx);
                                }
                            } else {
                                ui.label(RichText::new("✓ acked").small().weak());
                            }
                            ui.label(
                                RichText::new(alert.timestamp.format("%H:%M:%S").to_string())
                                    .small()
                                    .weak(),
                            );
                        });
                    });
                    ui.label(&alert.description);
                    if let (Some(pid), Some(name)) = (alert.process_pid, &alert.process_name) {
                        ui.label(
                            RichText::new(format!("PID: {pid}  Name: {name}"))
                                .small()
                                .weak(),
                        );
                    }
                });
            ui.add_space(2.0);
        }
    });

    if let Some(idx) = to_ack {
        state.alerts[idx].acknowledged = true;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Settings
// ═══════════════════════════════════════════════════════════════════════════════

fn show_settings(ui: &mut Ui, state: &mut AppState) {
    ScrollArea::vertical().show(ui, |ui| {
        ui.heading("⏱ Monitoring Intervals");
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Monitoring interval (ms):");
                ui.add(
                    egui::Slider::new(&mut state.config.monitoring_interval_ms, 500..=60_000)
                        .step_by(500.0)
                        .suffix(" ms"),
                );
            });
            ui.horizontal(|ui| {
                ui.label("DB log interval (s):");
                ui.add(
                    egui::Slider::new(&mut state.config.db_log_interval_secs, 5..=3600)
                        .step_by(5.0)
                        .suffix(" s"),
                );
            });
            ui.horizontal(|ui| {
                ui.label("History points:");
                ui.add(
                    egui::Slider::new(&mut state.config.max_history_points, 10..=300).step_by(10.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Database path:");
                ui.text_edit_singleline(&mut state.config.database_path);
            });
        });

        ui.add_space(8.0);
        ui.heading("🔥 CPU Thresholds");
        egui::Frame::group(ui.style()).show(ui, |ui| {
            threshold_slider(
                ui,
                "Warning (%)",
                &mut state.config.thresholds.cpu_warning_percent,
                10.0..=95.0,
            );
            threshold_slider(
                ui,
                "Critical (%)",
                &mut state.config.thresholds.cpu_critical_percent,
                10.0..=100.0,
            );
            threshold_slider(
                ui,
                "Per-process warning (%)",
                &mut state.config.thresholds.process_cpu_warning_percent,
                10.0..=100.0,
            );
        });

        ui.add_space(8.0);
        ui.heading("💾 Memory Thresholds");
        egui::Frame::group(ui.style()).show(ui, |ui| {
            threshold_slider(
                ui,
                "Warning (%)",
                &mut state.config.thresholds.memory_warning_percent,
                10.0..=95.0,
            );
            threshold_slider(
                ui,
                "Critical (%)",
                &mut state.config.thresholds.memory_critical_percent,
                10.0..=100.0,
            );
            ui.horizontal(|ui| {
                ui.label("Per-process memory warning (MB):");
                let mut mb = state.config.thresholds.process_memory_warning_mb as f64;
                if ui
                    .add(
                        egui::Slider::new(&mut mb, 128.0..=32768.0)
                            .step_by(128.0)
                            .suffix(" MB"),
                    )
                    .changed()
                {
                    state.config.thresholds.process_memory_warning_mb = mb as u64;
                }
            });
        });

        ui.add_space(8.0);
        ui.heading("💿 Disk Thresholds");
        egui::Frame::group(ui.style()).show(ui, |ui| {
            threshold_slider(
                ui,
                "Warning (%)",
                &mut state.config.thresholds.disk_warning_percent,
                50.0..=95.0,
            );
            threshold_slider(
                ui,
                "Critical (%)",
                &mut state.config.thresholds.disk_critical_percent,
                50.0..=100.0,
            );
        });

        ui.add_space(8.0);
        ui.heading("🌡 Temperature Thresholds");
        egui::Frame::group(ui.style()).show(ui, |ui| {
            threshold_slider(
                ui,
                "Warning (°C)",
                &mut state.config.thresholds.temp_warning_celsius,
                40.0..=95.0,
            );
            threshold_slider(
                ui,
                "Critical (°C)",
                &mut state.config.thresholds.temp_critical_celsius,
                50.0..=110.0,
            );
        });

        ui.add_space(8.0);
        ui.heading("🌐 Network Thresholds");
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Max bytes/s per interface:");
                let mut mb = state.config.thresholds.network_bytes_per_sec_threshold as f64 / 1e6;
                if ui
                    .add(
                        egui::Slider::new(&mut mb, 1.0..=10_000.0)
                            .step_by(10.0)
                            .suffix(" MB/s"),
                    )
                    .changed()
                {
                    state.config.thresholds.network_bytes_per_sec_threshold = (mb * 1e6) as u64;
                }
            });
        });

        ui.add_space(8.0);
        ui.heading("🔍 Risk Detection");
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Memory-leak detection samples:");
                ui.add(egui::Slider::new(
                    &mut state.config.thresholds.memory_leak_samples,
                    3..=20,
                ));
            });
        });

        ui.add_space(8.0);
        if ui.button("↺  Restore defaults").clicked() {
            state.config = crate::config::AppConfig::default();
        }
    });
}

fn threshold_slider(ui: &mut Ui, label: &str, val: &mut f32, range: std::ops::RangeInclusive<f32>) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::Slider::new(val, range).step_by(1.0));
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn metric_card(ui: &mut Ui, label: &str, value_percent: f32, color: Color32) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(140.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(label).strong().small());
            ui.add_space(2.0);
            ui.add(
                egui::ProgressBar::new((value_percent / 100.0).clamp(0.0, 1.0))
                    .desired_width(120.0)
                    .fill(color)
                    .text(format!("{:.1}%", value_percent)),
            );
        });
    });
}

fn history_plot(
    ui: &mut Ui,
    id: &str,
    data: &VecDeque<f32>,
    min_y: f64,
    max_y: f64,
    color: Color32,
    name: &str,
) {
    let pts: PlotPoints = data
        .iter()
        .enumerate()
        .map(|(i, &v)| [i as f64, v as f64])
        .collect();
    Plot::new(id)
        .height(140.0)
        .include_y(min_y)
        .include_y(max_y)
        .show_axes([false, true])
        .show(ui, |pu| {
            pu.line(Line::new(pts).color(color).name(name));
        });
}

fn alert_row(ui: &mut Ui, alert: &RiskAlert) {
    let (r, g, b) = alert.risk_level.rgb();
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("[{}]", alert.risk_level.label()))
                .strong()
                .color(Color32::from_rgb(r, g, b)),
        );
        ui.label(alert.category.icon());
        ui.label(&alert.description);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(alert.timestamp.format("%H:%M:%S").to_string())
                    .small()
                    .weak(),
            );
        });
    });
}

fn risk_badge(ui: &mut Ui, level: &RiskLevel) {
    let (r, g, b) = level.rgb();
    ui.label(
        RichText::new(level.label())
            .small()
            .color(Color32::from_rgb(r, g, b)),
    );
}

fn proc_risk_level(
    proc: &crate::models::ProcessInfo,
    t: &crate::config::AlertThresholds,
) -> RiskLevel {
    if proc.cpu_usage_percent >= 80.0
        || proc.memory_bytes / (1024 * 1024) >= t.process_memory_warning_mb * 2
    {
        return RiskLevel::High;
    }
    if proc.cpu_usage_percent >= t.process_cpu_warning_percent
        || proc.memory_bytes / (1024 * 1024) >= t.process_memory_warning_mb
    {
        return RiskLevel::Medium;
    }
    RiskLevel::Info
}

fn risk_row_color(level: &RiskLevel) -> Color32 {
    match level {
        RiskLevel::Info | RiskLevel::Low => Color32::GRAY,
        RiskLevel::Medium => Color32::from_rgb(255, 200, 100),
        RiskLevel::High | RiskLevel::Critical => Color32::from_rgb(255, 100, 100),
    }
}

// ─── Colour helpers ───────────────────────────────────────────────────────────

fn cpu_color(pct: f32) -> Color32 {
    if pct >= 90.0 {
        Color32::from_rgb(220, 20, 60)
    } else if pct >= 70.0 {
        Color32::from_rgb(255, 140, 0)
    } else {
        Color32::from_rgb(50, 200, 80)
    }
}

fn mem_color(pct: f32) -> Color32 {
    if pct >= 90.0 {
        Color32::from_rgb(220, 20, 60)
    } else if pct >= 75.0 {
        Color32::from_rgb(255, 140, 0)
    } else {
        Color32::from_rgb(100, 149, 237)
    }
}

fn temp_color(c: f32) -> Color32 {
    if c >= 95.0 {
        Color32::from_rgb(220, 20, 60)
    } else if c >= 80.0 {
        Color32::from_rgb(255, 140, 0)
    } else {
        Color32::from_rgb(50, 200, 80)
    }
}

fn disk_color(pct: f32) -> Color32 {
    if pct >= 95.0 {
        Color32::from_rgb(220, 20, 60)
    } else if pct >= 85.0 {
        Color32::from_rgb(255, 140, 0)
    } else {
        Color32::from_rgb(100, 200, 100)
    }
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {h:02}h {m:02}m")
    } else {
        format!("{h:02}h {m:02}m")
    }
}

#[allow(dead_code)]
pub fn bytes_to_human(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if b >= GB {
        format!("{:.2} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.0} KB", b as f64 / KB as f64)
    } else {
        format!("{b} B")
    }
}

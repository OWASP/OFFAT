//! Cross-platform desktop GUI (egui / eframe).
//!
//! Only compiled with the `gui` feature, so the default build stays a graphics-free
//! CLI. `offat-proxy gui` opens a window showing live flows, a detail pane, scope
//! and rule status, and a filter box using the same expression language as the
//! rules engine. It reads the shared flow store read-only; it never alters traffic.

use crate::flow::Flow;
use crate::proxy::ProxyRuntime;
use crate::rule::{parse_expr, ParsedExpr};
use crate::view;
use eframe::egui;
use std::sync::Arc;
use std::time::Duration;

/// Launch the GUI event loop (blocking; must run on the main thread).
pub fn run(rt: Arc<ProxyRuntime>) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "offat-proxy",
        options,
        Box::new(|_cc| Ok(Box::new(GuiApp::new(rt)) as Box<dyn eframe::App>)),
    )
    .map_err(|e| anyhow::anyhow!("gui error: {e}"))
}

struct GuiApp {
    rt: Arc<ProxyRuntime>,
    flows: Vec<Flow>,
    filter_text: String,
    filter: Option<ParsedExpr>,
    filter_error: Option<String>,
    selected: Option<String>,
}

impl GuiApp {
    fn new(rt: Arc<ProxyRuntime>) -> Self {
        Self {
            rt,
            flows: Vec::new(),
            filter_text: String::new(),
            filter: None,
            filter_error: None,
            selected: None,
        }
    }

    fn apply_filter(&mut self) {
        let src = self.filter_text.trim();
        if src.is_empty() {
            self.filter = None;
            self.filter_error = None;
            return;
        }
        match parse_expr(src) {
            Ok(e) => {
                self.filter = Some(e);
                self.filter_error = None;
            }
            Err(e) => {
                self.filter = None;
                self.filter_error = Some(e);
            }
        }
    }
}

fn class_color(class: &str) -> egui::Color32 {
    match class {
        "blocked" => egui::Color32::from_rgb(200, 100, 220),
        "error" | "5xx" => egui::Color32::from_rgb(230, 90, 90),
        "4xx" => egui::Color32::from_rgb(220, 180, 70),
        "2xx" => egui::Color32::from_rgb(110, 200, 110),
        _ => egui::Color32::GRAY,
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Pull the latest flows and keep repainting so the view stays live.
        self.flows = self.rt.state.all();
        ctx.request_repaint_after(Duration::from_millis(300));

        let scope = self.rt.state.scope_snapshot();
        let rules = self.rt.state.rules_snapshot().rules.len();
        let listen = self.rt.state.config.listen;
        let mitm = self.rt.state.config.mitm;
        let redact = self.rt.state.config.redact;

        // Bind locals the egui closures read/mutate, so they don't capture `self`
        // (which would conflict `&self.flows` with `&mut self.selected`). State is
        // written back after the panels close.
        let flows = &self.flows;
        let vis = view::visible_indices(flows, &self.filter);
        let total = flows.len();
        let scope_label = if scope.is_empty() {
            "(none)".to_string()
        } else {
            scope.include.join(",")
        };
        let filter_error = self.filter_error.clone();
        let mut filter_text = std::mem::take(&mut self.filter_text);
        let mut filter_dirty = false;
        let mut selection = self.selected.clone();

        egui::TopBottomPanel::top("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.strong("offat-proxy");
                ui.separator();
                ui.label(format!("listen {listen}"));
                ui.separator();
                ui.label(format!("flows {}/{}", vis.len(), total));
                ui.separator();
                ui.label(format!("scope {scope_label}"));
                ui.separator();
                ui.label(format!("mitm {}", on_off(mitm)));
                ui.separator();
                ui.label(format!("redact {}", on_off(redact)));
                ui.separator();
                ui.label(format!("rules {rules}"));
            });
            ui.horizontal(|ui| {
                ui.label("filter:");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut filter_text)
                        .hint_text("e.g. status >= 500 && path contains \"/api\"")
                        .desired_width(500.0),
                );
                if resp.changed() {
                    filter_dirty = true;
                }
                if ui.button("clear").clicked() {
                    filter_text.clear();
                    filter_dirty = true;
                }
                if let Some(e) = &filter_error {
                    ui.colored_label(
                        egui::Color32::from_rgb(230, 90, 90),
                        format!("filter error: {e}"),
                    );
                }
            });
        });

        egui::SidePanel::left("flows")
            .resizable(true)
            .default_width(480.0)
            .show(ctx, |ui| {
                ui.heading("flows");
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for &i in &vis {
                            let f = &flows[i];
                            let color = class_color(view::status_class(f));
                            let tag = if f.tags.is_empty() {
                                String::new()
                            } else {
                                format!("  [{}]", f.tags.join(","))
                            };
                            let scope_mark = if f.in_scope { "*" } else { " " };
                            let label = format!(
                                "{scope_mark}{:<5} {:>3} {}{}{}",
                                f.request.method,
                                view::status_label(f),
                                f.request.host,
                                f.request.path,
                                tag,
                            );
                            let is_sel = selection.as_deref() == Some(f.id.as_str());
                            if ui
                                .selectable_label(
                                    is_sel,
                                    egui::RichText::new(label).monospace().color(color),
                                )
                                .clicked()
                            {
                                selection = Some(f.id.clone());
                            }
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let selected = selection
                .as_ref()
                .and_then(|id| flows.iter().find(|f| &f.id == id));
            match selected {
                Some(f) => render_detail(ui, f),
                None => {
                    ui.label("Select a flow to see request and response details.");
                }
            }
        });

        // Write state back now that the borrows of `self.flows` are released.
        self.filter_text = filter_text;
        self.selected = selection;
        if filter_dirty {
            self.apply_filter();
        }
    }
}

fn render_detail(ui: &mut egui::Ui, f: &Flow) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.heading("Request");
            ui.monospace(format!("{} {}", f.request.method, f.url()));
            ui.monospace(format!(
                "in_scope={}  intercepted={}  tags=[{}]",
                f.in_scope,
                f.intercepted,
                f.tags.join(",")
            ));
            ui.add_space(4.0);
            for h in &f.request.headers {
                ui.monospace(format!("{}: {}", h.name, h.value));
            }
            if !f.request.body.is_empty() {
                ui.add_space(4.0);
                ui.monospace(&f.request.body);
            }

            ui.separator();
            ui.heading("Response");
            match &f.response {
                Some(r) => {
                    ui.monospace(format!(
                        "status={}  {}  {}  ({} ms)",
                        r.status,
                        r.http_version,
                        r.content_type,
                        f.latency_ms.unwrap_or(0)
                    ));
                    ui.add_space(4.0);
                    for h in &r.headers {
                        ui.monospace(format!("{}: {}", h.name, h.value));
                    }
                    if !r.body.is_empty() {
                        ui.add_space(4.0);
                        ui.monospace(&r.body);
                    }
                }
                None => {
                    if let Some(e) = &f.error {
                        ui.colored_label(
                            egui::Color32::from_rgb(230, 90, 90),
                            format!("error: {e}"),
                        );
                    } else {
                        ui.label("(pending)");
                    }
                }
            }
        });
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

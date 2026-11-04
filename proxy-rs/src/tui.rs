//! Terminal UI for the proxy: a live flow viewer with a detail pane and an
//! expression filter box (the same language the rule engine uses).
//!
//! `offat-proxy tui` runs the proxy and this UI in one process. The UI reads the
//! shared flow store each tick and renders read-only; it never changes traffic.
//! Rendering is a pure function of [`App`], so it is unit-tested headlessly with
//! ratatui's `TestBackend` (no real terminal needed).

use crate::flow::Flow;
use crate::proxy::ProxyRuntime;
use crate::rule::{parse_expr, ParsedExpr};
use anyhow::Result;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Focus {
    List,
    Detail,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Normal,
    Filter,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Action {
    Continue,
    Quit,
}

/// A snapshot of proxy status shown in the header (kept on `App` so rendering
/// needs no access to the runtime).
#[derive(Clone, Default)]
pub struct Status {
    pub listen: String,
    pub scope: String,
    pub mitm: bool,
    pub redact: bool,
    pub rules: usize,
}

pub struct App {
    pub flows: Vec<Flow>,
    pub status: Status,
    pub selected: usize,
    pub detail_scroll: u16,
    pub focus: Focus,
    pub mode: Mode,
    pub filter_input: String,
    pub filter: Option<ParsedExpr>,
    pub filter_error: Option<String>,
    pub show_help: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            flows: Vec::new(),
            status: Status::default(),
            selected: 0,
            detail_scroll: 0,
            focus: Focus::List,
            mode: Mode::Normal,
            filter_input: String::new(),
            filter: None,
            filter_error: None,
            show_help: false,
        }
    }
}

impl App {
    /// Indices into `flows` that pass the active filter (chronological order).
    pub fn visible(&self) -> Vec<usize> {
        crate::view::visible_indices(&self.flows, &self.filter)
    }

    /// Refresh from the latest flow snapshot, keeping the selection in range.
    pub fn sync(&mut self, flows: Vec<Flow>, status: Status) {
        self.flows = flows;
        self.status = status;
        let n = self.visible().len();
        if n == 0 {
            self.selected = 0;
        } else if self.selected >= n {
            self.selected = n - 1;
        }
    }

    pub fn selected_flow(&self) -> Option<&Flow> {
        let vis = self.visible();
        vis.get(self.selected).map(|&i| &self.flows[i])
    }

    /// Handle a key press, mutating state; returns whether to keep running.
    pub fn on_key(&mut self, code: KeyCode) -> Action {
        if self.mode == Mode::Filter {
            match code {
                KeyCode::Esc => self.mode = Mode::Normal,
                KeyCode::Enter => {
                    self.apply_filter();
                    self.mode = Mode::Normal;
                }
                KeyCode::Backspace => {
                    self.filter_input.pop();
                }
                KeyCode::Char(c) => self.filter_input.push(c),
                _ => {}
            }
            return Action::Continue;
        }

        let visible_len = self.visible().len();
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Char('?') => self.show_help = !self.show_help,
            KeyCode::Char('/') => {
                self.mode = Mode::Filter;
                self.filter_error = None;
            }
            KeyCode::Char('c') => {
                self.filter = None;
                self.filter_input.clear();
                self.filter_error = None;
            }
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::List => Focus::Detail,
                    Focus::Detail => Focus::List,
                };
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.focus == Focus::Detail {
                    self.detail_scroll = self.detail_scroll.saturating_add(1);
                } else if visible_len > 0 && self.selected + 1 < visible_len {
                    self.selected += 1;
                    self.detail_scroll = 0;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.focus == Focus::Detail {
                    self.detail_scroll = self.detail_scroll.saturating_sub(1);
                } else if self.selected > 0 {
                    self.selected -= 1;
                    self.detail_scroll = 0;
                }
            }
            KeyCode::Char('g') => {
                self.selected = 0;
                self.detail_scroll = 0;
            }
            KeyCode::Char('G') => {
                self.selected = visible_len.saturating_sub(1);
                self.detail_scroll = 0;
            }
            KeyCode::PageDown | KeyCode::Char('f') => {
                self.detail_scroll = self.detail_scroll.saturating_add(10)
            }
            KeyCode::PageUp | KeyCode::Char('b') => {
                self.detail_scroll = self.detail_scroll.saturating_sub(10)
            }
            _ => {}
        }
        Action::Continue
    }

    fn apply_filter(&mut self) {
        let src = self.filter_input.trim();
        if src.is_empty() {
            self.filter = None;
            self.filter_error = None;
            return;
        }
        match parse_expr(src) {
            Ok(e) => {
                self.filter = Some(e);
                self.filter_error = None;
                self.selected = 0;
            }
            Err(e) => {
                self.filter = None;
                self.filter_error = Some(e);
            }
        }
    }
}

// Re-export the key code type so main/tests use one path.
pub use crossterm::event::KeyCode;

/// Run the TUI event loop (blocking). The proxy runs on background tasks.
pub fn run(rt: Arc<ProxyRuntime>) -> Result<()> {
    use crossterm::event::{self, Event, KeyEventKind};
    use crossterm::execute;
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::default();
    let result = (|| -> Result<()> {
        loop {
            app.sync(rt.state.all(), status_from(&rt));
            terminal.draw(|f| render(f, &app))?;
            if event::poll(Duration::from_millis(250))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Release && app.on_key(key.code) == Action::Quit {
                        break;
                    }
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

pub fn status_from(rt: &Arc<ProxyRuntime>) -> Status {
    let scope = rt.state.scope_snapshot();
    let scope_str = if scope.is_empty() {
        "(none)".to_string()
    } else {
        scope.include.join(",")
    };
    Status {
        listen: rt.state.config.listen.to_string(),
        scope: scope_str,
        mitm: rt.state.config.mitm,
        redact: rt.state.config.redact,
        rules: rt.state.rules_snapshot().rules.len(),
    }
}

/// Render the whole UI. Pure function of `App` (testable with `TestBackend`).
pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(3),    // body
            Constraint::Length(1), // footer
        ])
        .split(area);

    render_header(frame, chunks[0], app);
    render_body(frame, chunks[1], app);
    render_footer(frame, chunks[2], app);

    if app.show_help {
        render_help(frame, area);
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.status;
    let filter = match (&app.filter_error, app.filter.is_some()) {
        (Some(e), _) => format!("  filter!=[{e}]"),
        (None, true) => format!("  filter=[{}]", app.filter_input),
        (None, false) => String::new(),
    };
    let text = format!(
        " offat-proxy  listen={}  flows={}/{}  scope={}  mitm={}  redact={}  rules={}{}",
        s.listen,
        app.visible().len(),
        app.flows.len(),
        s.scope,
        on_off(s.mitm),
        on_off(s.redact),
        s.rules,
        filter,
    );
    let p = Paragraph::new(text).style(Style::default().bg(Color::Blue).fg(Color::White));
    frame.render_widget(p, area);
}

fn render_body(frame: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);
    render_list(frame, cols[0], app);
    render_detail(frame, cols[1], app);
}

fn render_list(frame: &mut Frame, area: Rect, app: &App) {
    let vis = app.visible();
    let items: Vec<ListItem> = vis
        .iter()
        .map(|&i| {
            let f = &app.flows[i];
            let status = crate::view::status_label(f);
            let tag = if f.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", f.tags.join(","))
            };
            let scope_mark = if f.in_scope { "*" } else { " " };
            let line = format!(
                "{scope_mark}{:<4} {:>3} {}{}{}",
                f.request.method,
                status,
                f.request.host,
                truncate(&f.request.path, 28),
                tag,
            );
            let style = status_style(f);
            ListItem::new(Line::from(Span::styled(line, style)))
        })
        .collect();

    let border = focus_border(app.focus == Focus::List);
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("flows")
                .border_style(border),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    let mut state = ListState::default();
    if !app.visible().is_empty() {
        state.select(Some(app.selected.min(app.visible().len() - 1)));
    }
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_detail(frame: &mut Frame, area: Rect, app: &App) {
    let border = focus_border(app.focus == Focus::Detail);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("detail")
        .border_style(border);

    let lines = match app.selected_flow() {
        Some(f) => detail_lines(f),
        None => vec![Line::from("no flow selected")],
    };
    let p = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));
    frame.render_widget(p, area);
}

fn detail_lines(f: &Flow) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let hdr = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    out.push(Line::from(Span::styled("REQUEST", hdr)));
    out.push(Line::from(format!("{} {}", f.request.method, f.url())));
    out.push(Line::from(format!(
        "in_scope={} intercepted={} tags=[{}]",
        f.in_scope,
        f.intercepted,
        f.tags.join(",")
    )));
    for h in &f.request.headers {
        out.push(Line::from(format!("  {}: {}", h.name, h.value)));
    }
    if !f.request.body.is_empty() {
        out.push(Line::from(""));
        for l in f.request.body.lines().take(40) {
            out.push(Line::from(format!("  {l}")));
        }
    }
    out.push(Line::from(""));
    out.push(Line::from(Span::styled("RESPONSE", hdr)));
    match &f.response {
        Some(r) => {
            out.push(Line::from(format!(
                "status={} {} {} ({} ms)",
                r.status,
                r.http_version,
                r.content_type,
                f.latency_ms.unwrap_or(0)
            )));
            for h in &r.headers {
                out.push(Line::from(format!("  {}: {}", h.name, h.value)));
            }
            if !r.body.is_empty() {
                out.push(Line::from(""));
                for l in r.body.lines().take(80) {
                    out.push(Line::from(format!("  {l}")));
                }
            }
        }
        None => {
            if let Some(e) = &f.error {
                out.push(Line::from(format!("error: {e}")));
            } else {
                out.push(Line::from("(pending)"));
            }
        }
    }
    out
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let text = match app.mode {
        Mode::Filter => format!(" filter> {}_   (Enter apply, Esc cancel)", app.filter_input),
        Mode::Normal => {
            " j/k move  Tab focus  / filter  c clear  g/G top/bottom  f/b scroll  ? help  q quit"
                .to_string()
        }
    };
    let style = if app.mode == Mode::Filter {
        Style::default().bg(Color::Yellow).fg(Color::Black)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    frame.render_widget(Paragraph::new(text).style(style), area);
}

fn render_help(frame: &mut Frame, area: Rect) {
    let w = 60.min(area.width.saturating_sub(4));
    let h = 14.min(area.height.saturating_sub(2));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let popup = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    let lines = vec![
        Line::from("offat-proxy TUI"),
        Line::from(""),
        Line::from("j / k, arrows   move selection / scroll detail"),
        Line::from("Tab             switch focus (list <-> detail)"),
        Line::from("g / G           first / last flow"),
        Line::from("f / b, PgDn/Up  scroll detail"),
        Line::from("/               filter (expression language)"),
        Line::from("c               clear filter"),
        Line::from("?               toggle this help"),
        Line::from("q / Esc         quit"),
        Line::from(""),
        Line::from("filter e.g.: status >= 500 && path contains \"/api\""),
    ];
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("help")),
        popup,
    );
}

// --- helpers ---

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

fn focus_border(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn status_style(f: &Flow) -> Style {
    let color = match crate::view::status_class(f) {
        "blocked" => Color::Magenta,
        "error" | "5xx" => Color::Red,
        "4xx" => Color::Yellow,
        "2xx" => Color::Green,
        _ => Color::Gray,
    };
    Style::default().fg(color)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{t}…")
    }
}

/// Render an `App` to a string of the given size (used by tests).
#[cfg(test)]
pub fn render_to_string(app: &App, w: u16, h: u16) -> String {
    use ratatui::backend::TestBackend;
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, app)).unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Header, Request, Response};

    fn flow(method: &str, host: &str, path: &str, status: u16, scope: bool) -> Flow {
        let mut f = Flow::new(
            "c".into(),
            Request {
                method: method.into(),
                scheme: "https".into(),
                host: host.into(),
                path: path.into(),
                http_version: "HTTP/1.1".into(),
                headers: vec![Header {
                    name: "Accept".into(),
                    value: "*/*".into(),
                }],
                body: String::new(),
                body_truncated: false,
            },
            scope,
            true,
        );
        f.response = Some(Response {
            status,
            http_version: "HTTP/1.1".into(),
            content_type: "application/json".into(),
            headers: vec![],
            body: "{\"ok\":true}".into(),
            body_truncated: false,
        });
        f.latency_ms = Some(7);
        f
    }

    fn app_with_flows() -> App {
        let mut app = App::default();
        app.sync(
            vec![
                flow("GET", "api.example.test", "/users/1", 200, true),
                flow("POST", "api.example.test", "/login", 500, true),
                flow("GET", "cdn.other.test", "/img.png", 404, false),
            ],
            Status {
                listen: "127.0.0.1:8080".into(),
                scope: "api.example.test".into(),
                mitm: true,
                redact: true,
                rules: 2,
            },
        );
        app
    }

    #[test]
    fn renders_flows_and_status() {
        let s = render_to_string(&app_with_flows(), 120, 24);
        assert!(s.contains("offat-proxy"));
        assert!(s.contains("listen=127.0.0.1:8080"));
        assert!(s.contains("api.example.test"));
        assert!(s.contains("/login"));
        assert!(s.contains("mitm=on"));
        assert!(s.contains("rules=2"));
    }

    #[test]
    fn filter_limits_visible_flows() {
        let mut app = app_with_flows();
        app.filter_input = "status >= 500".into();
        app.apply_filter();
        let vis = app.visible();
        assert_eq!(vis.len(), 1);
        assert_eq!(app.flows[vis[0]].request.path, "/login");
        let s = render_to_string(&app, 120, 24);
        assert!(s.contains("flows=1/3"));
    }

    #[test]
    fn bad_filter_sets_error_and_keeps_all() {
        let mut app = app_with_flows();
        app.filter_input = "status >=".into();
        app.apply_filter();
        assert!(app.filter.is_none());
        assert!(app.filter_error.is_some());
        assert_eq!(app.visible().len(), 3);
    }

    #[test]
    fn navigation_moves_and_clamps() {
        let mut app = app_with_flows();
        assert_eq!(app.selected, 0);
        app.on_key(KeyCode::Char('j'));
        assert_eq!(app.selected, 1);
        app.on_key(KeyCode::Char('G'));
        assert_eq!(app.selected, 2);
        // can't go past the end
        app.on_key(KeyCode::Char('j'));
        assert_eq!(app.selected, 2);
        app.on_key(KeyCode::Char('g'));
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn quit_key() {
        let mut app = app_with_flows();
        assert_eq!(app.on_key(KeyCode::Char('q')), Action::Quit);
    }

    #[test]
    fn filter_mode_typing() {
        let mut app = app_with_flows();
        app.on_key(KeyCode::Char('/'));
        assert_eq!(app.mode, Mode::Filter);
        for c in "status".chars() {
            app.on_key(KeyCode::Char(c));
        }
        app.on_key(KeyCode::Backspace);
        assert_eq!(app.filter_input, "statu");
        app.on_key(KeyCode::Esc);
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn detail_shows_selected_flow() {
        let mut app = app_with_flows();
        app.on_key(KeyCode::Char('j')); // select /login (500)
        let s = render_to_string(&app, 120, 30);
        assert!(s.contains("REQUEST"));
        assert!(s.contains("RESPONSE"));
        assert!(s.contains("status=500"));
    }
}

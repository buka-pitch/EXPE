//! Model–view–update state for the console.
//!
//! Every key becomes a [`Msg`], [`App::update`] is the only place that mutates
//! state, and external work is expressed as an [`Effect`]. This keeps the UI
//! deterministic and makes the navigation/filter logic unit-testable without a
//! terminal.

use std::path::PathBuf;

use expe_core::{
    AnalysisOutcome, AnalysisReport, ExtractedString, Finding, Ioc, IocKind, Section, Severity,
    Structure,
};
use expe_engine::Stage;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json;

use crate::worker::WorkerMsg;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Open,
    Overview,
    Structure,
    Strings,
    Iocs,
    Findings,
    Hex,
}

impl Screen {
    pub const NAV: [Self; 6] = [
        Self::Overview,
        Self::Structure,
        Self::Strings,
        Self::Iocs,
        Self::Findings,
        Self::Hex,
    ];

    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Overview => "OVERVIEW",
            Self::Structure => "STRUCTURE",
            Self::Strings => "STRINGS",
            Self::Iocs => "INDICATORS",
            Self::Findings => "FINDINGS",
            Self::Hex => "HEX",
        }
    }

    #[must_use]
    pub fn icon(self, ascii: bool) -> &'static str {
        match (self, ascii) {
            (Self::Open, _) => "~",
            (Self::Overview, true) => "O",
            (Self::Overview, false) => "◈",
            (Self::Structure, true) => "S",
            (Self::Structure, false) => "▦",
            (Self::Strings, true) => "T",
            (Self::Strings, false) => "≡",
            (Self::Iocs, true) => "I",
            (Self::Iocs, false) => "⌁",
            (Self::Findings, true) => "!",
            (Self::Findings, false) => "⚠",
            (Self::Hex, true) => "H",
            (Self::Hex, false) => "⌗",
        }
    }

    #[must_use]
    pub fn nav_index(self) -> Option<usize> {
        Self::NAV.iter().position(|screen| *screen == self)
    }

    #[must_use]
    pub fn is_filterable(self) -> bool {
        matches!(
            self,
            Self::Structure | Self::Strings | Self::Iocs | Self::Findings
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Idle,
    Analyzing,
    Ready,
    Failed(String),
}

impl Status {
    #[must_use]
    pub fn is_analyzing(&self) -> bool {
        matches!(self, Self::Analyzing)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    OpenPath,
    Filter,
    GotoHex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Good,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub kind: ToastKind,
    pub ttl: u16,
}

#[derive(Debug)]
pub enum Effect {
    Quit,
    Analyze(PathBuf),
    CancelAnalysis,
    Export { path: PathBuf, bytes: Vec<u8> },
    Copy(String),
}

#[derive(Debug)]
pub enum Msg {
    Tick,
    Key(KeyEvent),
    Worker(WorkerMsg),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SeverityCounts {
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

impl SeverityCounts {
    #[must_use]
    pub fn actionable(self) -> usize {
        self.low + self.medium + self.high + self.critical
    }
}

const TOAST_TTL: u16 = 34;
const OPEN_PATH_LIMIT: usize = 4096;

// The console keeps independent view, overlay and process flags together.
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    pub screen: Screen,
    pub status: Status,
    pub report: Option<AnalysisReport>,
    pub raw: Option<std::sync::Arc<[u8]>>,
    pub path: Option<PathBuf>,
    pub stage: Stage,
    pub tick: u64,
    pub open_path: String,
    pub input: InputMode,
    pub filter: String,
    pub goto_buf: String,
    pub defang: bool,
    pub show_help: bool,
    pub toast: Option<Toast>,
    pub should_quit: bool,
    pub ascii: bool,
    pub viewport_height: usize,

    pub structure_selected: usize,
    pub structure_scroll: usize,
    pub strings_selected: usize,
    pub strings_scroll: usize,
    pub iocs_selected: usize,
    pub iocs_scroll: usize,
    pub findings_selected: usize,
    pub findings_scroll: usize,

    pub hex_offset: u64,
    pub hex_mark: Option<u64>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            screen: Screen::Open,
            status: Status::Idle,
            report: None,
            raw: None,
            path: None,
            stage: Stage::Reading,
            tick: 0,
            open_path: String::new(),
            input: InputMode::OpenPath,
            filter: String::new(),
            goto_buf: String::new(),
            defang: false,
            show_help: false,
            toast: None,
            should_quit: false,
            ascii: std::env::var_os("EXPE_ASCII").is_some(),
            viewport_height: 18,
            structure_selected: 0,
            structure_scroll: 0,
            strings_selected: 0,
            strings_scroll: 0,
            iocs_selected: 0,
            iocs_scroll: 0,
            findings_selected: 0,
            findings_scroll: 0,
            hex_offset: 0,
            hex_mark: None,
        }
    }
}

impl App {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, msg: Msg) -> Vec<Effect> {
        match msg {
            Msg::Tick => {
                self.tick = self.tick.wrapping_add(1);
                if let Some(toast) = &mut self.toast {
                    if toast.ttl == 0 {
                        self.toast = None;
                    } else {
                        toast.ttl -= 1;
                    }
                }
                Vec::new()
            }
            Msg::Key(key) => self.handle_key(key),
            Msg::Worker(WorkerMsg::Stage(stage)) => {
                if self.status.is_analyzing() {
                    self.stage = stage;
                }
                Vec::new()
            }
            Msg::Worker(WorkerMsg::Done(result)) => self.finish_analysis(result),
        }
    }

    /// Start analysis, switching to the open/working card. The caller is
    /// responsible for spawning the worker when it sees [`Effect::Analyze`].
    pub fn request_analysis(&mut self, path: PathBuf) -> Vec<Effect> {
        if self.status.is_analyzing() {
            self.set_toast("An analysis is already running", ToastKind::Warn);
            return Vec::new();
        }
        self.open_path = path.display().to_string();
        self.path = Some(path.clone());
        self.status = Status::Analyzing;
        self.stage = Stage::Reading;
        self.screen = Screen::Open;
        self.input = InputMode::Normal;
        self.show_help = false;
        self.filter.clear();
        self.reset_selections();
        vec![Effect::Analyze(path)]
    }

    pub fn set_toast(&mut self, text: impl Into<String>, kind: ToastKind) {
        self.toast = Some(Toast {
            text: text.into(),
            kind,
            ttl: TOAST_TTL,
        });
    }

    fn finish_analysis(&mut self, result: Result<Box<AnalysisOutcome>, String>) -> Vec<Effect> {
        match result {
            Ok(outcome) => {
                let outcome = *outcome;
                let score = outcome.report.risk.score;
                let verdict = outcome.report.risk.verdict.label();
                self.report = Some(outcome.report);
                self.raw = outcome.raw;
                self.status = Status::Ready;
                self.screen = Screen::Overview;
                self.input = InputMode::Normal;
                self.filter.clear();
                self.reset_selections();
                self.set_toast(
                    format!("Analysis complete · risk {score} {verdict}"),
                    ToastKind::Good,
                );
            }
            Err(error) => {
                self.status = Status::Failed(error.clone());
                self.screen = Screen::Open;
                self.input = InputMode::OpenPath;
                self.set_toast(format!("Analysis failed: {error}"), ToastKind::Error);
            }
        }
        Vec::new()
    }

    fn handle_key(&mut self, key: KeyEvent) -> Vec<Effect> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && matches!(key.code, KeyCode::Char('c' | 'C')) {
            self.should_quit = true;
            return vec![Effect::Quit];
        }

        if self.show_help {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('?') | KeyCode::F(1)) {
                self.show_help = false;
            }
            return Vec::new();
        }

        match self.input {
            InputMode::OpenPath => self.handle_open_key(key, ctrl),
            InputMode::Filter => self.handle_filter_key(key, ctrl),
            InputMode::GotoHex => self.handle_goto_key(key, ctrl),
            InputMode::Normal => self.handle_normal_key(key, ctrl),
        }
    }

    fn handle_open_key(&mut self, key: KeyEvent, ctrl: bool) -> Vec<Effect> {
        if self.status.is_analyzing() {
            return match key.code {
                KeyCode::Esc => self.cancel_analysis(),
                KeyCode::Char('q') => {
                    self.should_quit = true;
                    vec![Effect::Quit]
                }
                KeyCode::Char('?') => {
                    self.show_help = true;
                    Vec::new()
                }
                _ => Vec::new(),
            };
        }

        match key.code {
            KeyCode::Char('u' | 'U') if ctrl => self.open_path.clear(),
            KeyCode::Backspace => {
                self.open_path.pop();
            }
            KeyCode::Char(ch) if !ctrl => {
                if self.open_path.chars().count() < OPEN_PATH_LIMIT {
                    self.open_path.push(ch);
                }
            }
            KeyCode::Enter => {
                let trimmed = self.open_path.trim();
                if trimmed.is_empty() {
                    self.set_toast("Enter a path to a PE, ELF or Mach-O file", ToastKind::Warn);
                } else {
                    return self.request_analysis(PathBuf::from(trimmed));
                }
            }
            KeyCode::Esc => {
                self.should_quit = true;
                return vec![Effect::Quit];
            }
            KeyCode::Tab if self.report.is_some() => self.set_screen(Screen::Overview),
            _ => {}
        }
        Vec::new()
    }

    fn handle_filter_key(&mut self, key: KeyEvent, ctrl: bool) -> Vec<Effect> {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.input = InputMode::Normal;
                self.reset_current_selection();
            }
            KeyCode::Enter => {
                self.input = InputMode::Normal;
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.reset_current_selection();
            }
            KeyCode::Char('u' | 'U') if ctrl => {
                self.filter.clear();
                self.reset_current_selection();
            }
            KeyCode::Char(ch) if !ctrl => {
                if self.filter.chars().count() < 120 {
                    self.filter.push(ch);
                    self.reset_current_selection();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            _ => {}
        }
        Vec::new()
    }

    fn handle_goto_key(&mut self, key: KeyEvent, ctrl: bool) -> Vec<Effect> {
        match key.code {
            KeyCode::Esc => {
                self.goto_buf.clear();
                self.input = InputMode::Normal;
            }
            KeyCode::Enter => {
                let raw = self
                    .goto_buf
                    .trim()
                    .trim_start_matches("0x")
                    .replace('_', "");
                self.goto_buf.clear();
                self.input = InputMode::Normal;
                if raw.is_empty() {
                    return Vec::new();
                }
                match u64::from_str_radix(&raw, 16) {
                    Ok(offset) => {
                        let max = self.raw.as_ref().map_or(0, |bytes| bytes.len() as u64);
                        self.hex_offset = offset.min(max.saturating_sub(1));
                        self.hex_mark = Some(offset);
                    }
                    Err(_) => self.set_toast("Offset must be hexadecimal", ToastKind::Error),
                }
            }
            KeyCode::Backspace => {
                self.goto_buf.pop();
            }
            KeyCode::Char('u' | 'U') if ctrl => self.goto_buf.clear(),
            KeyCode::Char(ch)
                if !ctrl
                    && (ch.is_ascii_hexdigit() || ch == 'x' || ch == 'X' || ch == '_')
                    && self.goto_buf.len() < 18 =>
            {
                self.goto_buf.push(ch);
            }
            _ => {}
        }
        Vec::new()
    }

    fn handle_normal_key(&mut self, key: KeyEvent, ctrl: bool) -> Vec<Effect> {
        if ctrl {
            return Vec::new();
        }
        if self.status.is_analyzing() {
            return match key.code {
                KeyCode::Esc => self.cancel_analysis(),
                KeyCode::Char('q') => {
                    self.should_quit = true;
                    vec![Effect::Quit]
                }
                KeyCode::Char('?') => {
                    self.show_help = true;
                    Vec::new()
                }
                _ => Vec::new(),
            };
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                return vec![Effect::Quit];
            }
            KeyCode::Char('?') | KeyCode::F(1) => self.show_help = true,
            KeyCode::Esc => {
                if self.screen == Screen::Open {
                    self.should_quit = true;
                    return vec![Effect::Quit];
                }
                self.set_screen(Screen::Overview);
            }
            KeyCode::Char('e') => match self.export_path() {
                Some((path, bytes)) => return vec![Effect::Export { path, bytes }],
                None => self.set_toast("Nothing to export yet", ToastKind::Warn),
            },
            KeyCode::Char('r') => {
                if let Some(path) = self.path.clone() {
                    return self.request_analysis(path);
                }
                self.set_toast("No sample to re-analyze", ToastKind::Warn);
            }
            KeyCode::Char('o') => {
                self.screen = Screen::Open;
                self.input = InputMode::OpenPath;
                if let Some(path) = &self.path {
                    self.open_path = path.display().to_string();
                }
            }
            KeyCode::Char('d') if self.report.is_some() => {
                self.defang = !self.defang;
                let state = if self.defang { "defanged" } else { "raw" };
                self.set_toast(format!("Indicator display: {state}"), ToastKind::Info);
            }
            KeyCode::Char('/') if self.screen.is_filterable() => {
                self.filter.clear();
                self.input = InputMode::Filter;
                self.reset_current_selection();
            }
            KeyCode::Char('g') if self.screen == Screen::Hex => {
                self.goto_buf.clear();
                self.input = InputMode::GotoHex;
            }
            KeyCode::Char('c') => {
                if let Some(payload) = self.copy_payload() {
                    self.set_toast("Copied to clipboard (OSC52)", ToastKind::Good);
                    return vec![Effect::Copy(payload)];
                }
                self.set_toast("Nothing selected to copy", ToastKind::Warn);
            }
            KeyCode::Char('x') | KeyCode::Enter => self.jump_to_hex(),
            KeyCode::Char(ch @ '1'..='6') => {
                let index = usize::from(ch as u8 - b'1');
                if let Some(screen) = Screen::NAV.get(index) {
                    self.set_screen(*screen);
                }
            }
            KeyCode::Tab | KeyCode::Right => self.cycle_screen(1),
            KeyCode::BackTab | KeyCode::Left => self.cycle_screen(-1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Home => self.move_selection_to(0),
            KeyCode::End => {
                let len = self.current_len();
                self.move_selection_to(len.saturating_sub(1));
            }
            _ => {}
        }
        Vec::new()
    }

    fn cancel_analysis(&mut self) -> Vec<Effect> {
        self.status = Status::Idle;
        self.stage = Stage::Reading;
        self.screen = Screen::Open;
        self.input = InputMode::OpenPath;
        self.set_toast(
            "Analysis cancelled; the worker will exit safely",
            ToastKind::Warn,
        );
        vec![Effect::CancelAnalysis]
    }

    fn set_screen(&mut self, screen: Screen) {
        if screen != Screen::Open && self.report.is_none() {
            return;
        }
        if self.screen == screen {
            self.input = InputMode::Normal;
            return;
        }
        self.screen = screen;
        self.input = InputMode::Normal;
        self.filter.clear();
        self.show_help = false;
    }

    fn cycle_screen(&mut self, delta: isize) {
        if self.report.is_none() {
            return;
        }
        let current = self.screen.nav_index().unwrap_or(0);
        let len = Screen::NAV.len();
        let next = (current.cast_signed() + delta).rem_euclid(len.cast_signed()) as usize;
        self.set_screen(Screen::NAV[next]);
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.current_len();
        if len == 0 {
            return;
        }
        let current = self.current_selected();
        let next = if delta.is_negative() {
            current.saturating_sub(delta.unsigned_abs())
        } else {
            (current + delta.unsigned_abs()).min(len - 1)
        };
        self.set_current_selected(next);
        self.ensure_current_visible(len);
    }

    fn move_selection_to(&mut self, index: usize) {
        let len = self.current_len();
        if len == 0 {
            return;
        }
        self.set_current_selected(index.min(len - 1));
        self.ensure_current_visible(len);
    }

    fn reset_current_selection(&mut self) {
        match self.screen {
            Screen::Structure => {
                self.structure_selected = 0;
                self.structure_scroll = 0;
            }
            Screen::Strings => {
                self.strings_selected = 0;
                self.strings_scroll = 0;
            }
            Screen::Iocs => {
                self.iocs_selected = 0;
                self.iocs_scroll = 0;
            }
            Screen::Findings => {
                self.findings_selected = 0;
                self.findings_scroll = 0;
            }
            _ => {}
        }
    }

    fn reset_selections(&mut self) {
        self.structure_selected = 0;
        self.structure_scroll = 0;
        self.strings_selected = 0;
        self.strings_scroll = 0;
        self.iocs_selected = 0;
        self.iocs_scroll = 0;
        self.findings_selected = 0;
        self.findings_scroll = 0;
        self.hex_offset = 0;
        self.hex_mark = None;
    }

    fn current_len(&self) -> usize {
        match self.screen {
            Screen::Structure => self.filtered_sections().len(),
            Screen::Strings => self.filtered_strings().len(),
            Screen::Iocs => self.filtered_iocs().len(),
            Screen::Findings => self.filtered_findings().len(),
            _ => 0,
        }
    }

    fn current_selected(&self) -> usize {
        match self.screen {
            Screen::Structure => self.structure_selected,
            Screen::Strings => self.strings_selected,
            Screen::Iocs => self.iocs_selected,
            Screen::Findings => self.findings_selected,
            _ => 0,
        }
    }

    fn set_current_selected(&mut self, value: usize) {
        match self.screen {
            Screen::Structure => self.structure_selected = value,
            Screen::Strings => self.strings_selected = value,
            Screen::Iocs => self.iocs_selected = value,
            Screen::Findings => self.findings_selected = value,
            _ => {}
        }
    }

    fn current_scroll(&self) -> usize {
        match self.screen {
            Screen::Structure => self.structure_scroll,
            Screen::Strings => self.strings_scroll,
            Screen::Iocs => self.iocs_scroll,
            Screen::Findings => self.findings_scroll,
            _ => 0,
        }
    }

    fn current_scroll_mut(&mut self) -> &mut usize {
        match self.screen {
            Screen::Strings => &mut self.strings_scroll,
            Screen::Iocs => &mut self.iocs_scroll,
            Screen::Findings => &mut self.findings_scroll,
            Screen::Open | Screen::Overview | Screen::Structure | Screen::Hex => {
                &mut self.structure_scroll
            }
        }
    }

    fn ensure_current_visible(&mut self, len: usize) {
        let height = self.viewport_height.max(1);
        let selected = self.current_selected();
        let scroll = self.current_scroll_mut();
        if selected < *scroll {
            *scroll = selected;
        } else if selected >= *scroll + height {
            *scroll = selected + 1 - height;
        }
        let max_scroll = len.saturating_sub(height);
        *scroll = (*scroll).min(max_scroll);
    }

    /// Called by each list renderer before it borrows the report. Clamps the
    /// scroll window to the new viewport height and the filtered row count.
    pub fn prepare_viewport(&mut self, height: usize) {
        self.viewport_height = height.max(1);
        let len = self.current_len();
        if len == 0 {
            let scroll = self.current_scroll_mut();
            *scroll = 0;
            return;
        }
        let selected = self.current_selected().min(len - 1);
        self.set_current_selected(selected);
        self.ensure_current_visible(len);
    }

    pub fn sections(&self) -> &[Section] {
        match self.report.as_ref().map(|report| &report.structure) {
            Some(Structure::Pe(info)) => &info.sections,
            Some(Structure::Elf(info)) => &info.sections,
            _ => &[],
        }
    }

    pub fn filtered_sections(&self) -> Vec<&Section> {
        let needle = self.filter.to_lowercase();
        self.sections()
            .iter()
            .filter(|section| {
                needle.is_empty()
                    || section.name.to_lowercase().contains(&needle)
                    || section.permissions.to_lowercase().contains(&needle)
            })
            .collect()
    }

    pub fn filtered_strings(&self) -> Vec<&ExtractedString> {
        let needle = self.filter.to_lowercase();
        self.report
            .as_ref()
            .map(|report| {
                report
                    .strings
                    .items
                    .iter()
                    .filter(|item| {
                        needle.is_empty()
                            || item.value.to_lowercase().contains(&needle)
                            || item.encoding.label().contains(&needle)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn filtered_iocs(&self) -> Vec<&Ioc> {
        let needle = self.filter.to_lowercase();
        self.report
            .as_ref()
            .map(|report| {
                report
                    .iocs
                    .iter()
                    .flat_map(|group| group.items.iter())
                    .filter(|item| {
                        needle.is_empty()
                            || item.value.to_lowercase().contains(&needle)
                            || item.defanged.to_lowercase().contains(&needle)
                            || item.kind.label().to_lowercase().contains(&needle)
                            || item.kind.as_str().contains(&needle)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn filtered_findings(&self) -> Vec<&Finding> {
        let needle = self.filter.to_lowercase();
        self.report
            .as_ref()
            .map(|report| {
                report
                    .sorted_findings()
                    .into_iter()
                    .filter(|finding| {
                        needle.is_empty()
                            || finding.id.to_lowercase().contains(&needle)
                            || finding.title.to_lowercase().contains(&needle)
                            || finding.evidence.to_lowercase().contains(&needle)
                            || finding.category.label().to_lowercase().contains(&needle)
                            || finding.severity.label().contains(&needle)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn selected_section(&self) -> Option<&Section> {
        self.filtered_sections()
            .get(self.structure_selected)
            .copied()
    }

    pub fn selected_string(&self) -> Option<&ExtractedString> {
        self.filtered_strings().get(self.strings_selected).copied()
    }

    pub fn selected_ioc(&self) -> Option<&Ioc> {
        self.filtered_iocs().get(self.iocs_selected).copied()
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        self.filtered_findings()
            .get(self.findings_selected)
            .copied()
    }

    pub fn ioc_kind_counts(&self) -> Vec<(IocKind, usize)> {
        self.report
            .as_ref()
            .map(|report| {
                report
                    .iocs
                    .iter()
                    .map(|group| (group.kind, group.items.len()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn severity_counts(&self) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        if let Some(report) = &self.report {
            for finding in &report.findings {
                match finding.severity {
                    Severity::Info => counts.info += 1,
                    Severity::Low => counts.low += 1,
                    Severity::Medium => counts.medium += 1,
                    Severity::High => counts.high += 1,
                    Severity::Critical => counts.critical += 1,
                }
            }
        }
        counts
    }

    fn copy_payload(&self) -> Option<String> {
        match self.screen {
            Screen::Strings => self.selected_string().map(|item| item.value.clone()),
            Screen::Iocs => self.selected_ioc().map(|item| item.value.clone()),
            Screen::Findings => self.selected_finding().map(|finding| {
                let mut out = format!(
                    "{} [{}] {}\n{}\n{}",
                    finding.id,
                    finding.severity.label(),
                    finding.title,
                    finding.category.label(),
                    finding.evidence
                );
                if !finding.attack.is_empty() {
                    out.push_str("\nATT&CK: ");
                    out.push_str(&finding.attack.join(", "));
                }
                out
            }),
            _ => None,
        }
    }

    fn jump_to_hex(&mut self) {
        let offset = match self.screen {
            Screen::Strings => self.selected_string().map(|item| item.offset),
            Screen::Iocs => self
                .selected_ioc()
                .and_then(|item| item.offsets.first().copied()),
            _ => None,
        };
        match offset {
            Some(offset) => {
                self.hex_offset = offset;
                self.hex_mark = Some(offset);
                self.set_screen(Screen::Hex);
            }
            None => self.set_toast("No source offset for this row", ToastKind::Warn),
        }
    }

    fn export_path(&self) -> Option<(PathBuf, Vec<u8>)> {
        let report = self.report.as_ref()?;
        let stem: String = report
            .artifact
            .file_name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                    ch
                } else {
                    '_'
                }
            })
            .take(80)
            .collect();
        let stem = stem.trim_matches(['.', '_']);
        let stem = if stem.is_empty() { "report" } else { stem };
        let path = PathBuf::from(format!("{stem}.expe.json"));
        let bytes = serde_json::to_vec_pretty(report).ok()?;
        Some((path, bytes))
    }

    #[must_use]
    // Stage positions are small fixed integers (1..=6), so f64 is exact here.
    #[allow(clippy::cast_precision_loss)]
    pub fn progress(&self) -> f64 {
        if self.status == Status::Ready {
            return 1.0;
        }
        self.stage.position() as f64 / Stage::total() as f64
    }

    #[must_use]
    pub fn spinner(&self) -> &'static str {
        let tick = usize::try_from(self.tick).unwrap_or(usize::MAX);
        if self.ascii {
            const FRAMES: [&str; 4] = ["|", "/", "-", "\\"];
            FRAMES[(tick / 2) % FRAMES.len()]
        } else {
            const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            FRAMES[(tick / 2) % FRAMES.len()]
        }
    }

    #[must_use]
    pub fn scroll(&self) -> usize {
        self.current_scroll()
    }

    pub fn scroll_hex(&mut self, bytes: i64) {
        let max = self.raw.as_ref().map_or(0, |raw| raw.len() as u64);
        let next = if bytes.is_negative() {
            self.hex_offset.saturating_sub(bytes.unsigned_abs())
        } else {
            self.hex_offset
                .saturating_add(bytes.unsigned_abs())
                .min(max.saturating_sub(1))
        };
        self.hex_offset = next;
        self.hex_mark = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyEvent;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn typing_a_path_and_enter_starts_analysis() {
        let mut app = App::new();
        for ch in "/tmp/sample".chars() {
            let effects = app.update(Msg::Key(key(KeyCode::Char(ch))));
            assert!(effects.is_empty());
        }
        let effects = app.update(Msg::Key(key(KeyCode::Enter)));
        assert!(
            matches!(effects.as_slice(), [Effect::Analyze(path)] if path == &PathBuf::from("/tmp/sample"))
        );
        assert!(app.status.is_analyzing());
    }

    #[test]
    fn escape_cancels_analysis() {
        let mut app = App::new();
        let effects = app.request_analysis(PathBuf::from("/tmp/x"));
        assert!(matches!(effects.as_slice(), [Effect::Analyze(_)]));
        let effects = app.update(Msg::Key(key(KeyCode::Esc)));
        assert!(matches!(effects.as_slice(), [Effect::CancelAnalysis]));
        assert_eq!(app.status, Status::Idle);
    }

    #[test]
    fn filter_is_applied_and_reset() {
        let mut app = App::new();
        app.filter = "MISSING".to_string();
        assert!(app.filtered_strings().is_empty());
        app.filter.clear();
        assert!(app.filtered_strings().is_empty());
    }

    #[test]
    fn selection_clamps_at_edges() {
        let mut app = App::new();
        app.screen = Screen::Strings;
        app.viewport_height = 5;
        app.move_selection(-1);
        app.move_selection(1);
        assert_eq!(app.strings_selected, 0);
    }

    fn sample_report() -> AnalysisReport {
        AnalysisReport {
            schema_version: expe_core::SCHEMA_VERSION.to_string(),
            tool: expe_core::ToolInfo {
                name: "EXPE".to_string(),
                version: "0.1.0".to_string(),
                schema_version: expe_core::SCHEMA_VERSION.to_string(),
                ruleset_version: "1.0.0".to_string(),
            },
            artifact: expe_core::Artifact {
                file_name: "sample.exe".to_string(),
                ..expe_core::Artifact::default()
            },
            structure: Structure::Unavailable,
            strings: expe_core::StringsSummary::default(),
            iocs: Vec::new(),
            findings: Vec::new(),
            risk: expe_core::Risk::clean(),
            limits: expe_core::LimitsReport::default(),
            timing_ms: 0,
        }
    }

    #[test]
    fn export_key_emits_json_effect() {
        let mut app = App::new();
        app.report = Some(sample_report());
        app.status = Status::Ready;
        app.screen = Screen::Overview;
        app.input = InputMode::Normal;

        let effects = app.update(Msg::Key(key(KeyCode::Char('e'))));
        match effects.as_slice() {
            [Effect::Export { path, bytes }] => {
                assert_eq!(path, &PathBuf::from("sample.exe.expe.json"));
                let parsed: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                assert_eq!(parsed["artifact"]["file_name"], "sample.exe");
                assert_eq!(parsed["tool"]["name"], "EXPE");
            }
            other => panic!("unexpected effects: {other:?}"),
        }
    }
}

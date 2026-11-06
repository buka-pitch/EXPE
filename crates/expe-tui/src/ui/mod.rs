mod findings;
mod footer;
mod header;
mod help;
mod hex;
mod iocs;
mod open;
mod overview;
mod sidebar;
mod strings;
mod structure;
mod theme;
mod toast;

use expe_core::Severity;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::app::{App, Screen, Status};
use crate::sanitize::{clip, clip_ascii, sanitize, sanitize_multiline};
use theme::Theme;

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    let theme = Theme::default();
    frame.render_widget(Block::default().style(theme.base()), area);

    if area.width < 58 || area.height < 17 {
        let message = format!(
            "EXPE needs at least 58×17 — current terminal is {}×{}",
            area.width, area.height
        );
        frame.render_widget(
            Paragraph::new(message)
                .alignment(Alignment::Center)
                .style(theme.muted_style())
                .block(Block::default().style(theme.base())),
            inner_area(area),
        );
        return;
    }

    let rows = Layout::vertical([
        Constraint::Length(4),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .split(area);

    header::draw(frame, rows[0], app, &theme);
    let body = Layout::horizontal([Constraint::Length(21), Constraint::Fill(1)]).split(rows[1]);
    sidebar::draw(frame, body[0], app, &theme);
    match app.screen {
        Screen::Open => open::draw(frame, body[1], app, &theme),
        Screen::Overview => overview::draw(frame, body[1], app, &theme),
        Screen::Structure => structure::draw(frame, body[1], app, &theme),
        Screen::Strings => strings::draw(frame, body[1], app, &theme),
        Screen::Iocs => iocs::draw(frame, body[1], app, &theme),
        Screen::Findings => findings::draw(frame, body[1], app, &theme),
        Screen::Hex => hex::draw(frame, body[1], app, &theme),
    }
    footer::draw(frame, rows[2], app, &theme);

    if app.show_help {
        help::draw(frame, area, &theme);
    }
    if app.toast.is_some() {
        toast::draw(frame, area, app, &theme);
    }
}

fn inner_area(area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .split(area);
    vertical[1]
}

pub(crate) fn empty_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    theme: &Theme,
    title: &str,
    message: &str,
) {
    let paragraph = Paragraph::new(sanitize(message))
        .style(theme.muted_style())
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(theme.panel(title));
    frame.render_widget(paragraph, area);
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2)).max(1);
    let height = height.min(area.height.saturating_sub(2)).max(1);
    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(height),
        Constraint::Fill(1),
    ])
    .split(area);
    let horizontal = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(width),
        Constraint::Fill(1),
    ])
    .split(vertical[1]);
    horizontal[1]
}

fn count_sections(report: &expe_core::AnalysisReport) -> usize {
    match &report.structure {
        expe_core::Structure::Pe(info) => info.sections.len(),
        expe_core::Structure::Elf(info) => info.sections.len(),
        expe_core::Structure::MachO(info) => info.segments.len(),
        expe_core::Structure::Unavailable => 0,
    }
}

fn severity_chip(theme: &Theme, severity: Severity) -> Span<'static> {
    Span::styled(
        format!(" {} ", severity.label().to_uppercase()),
        theme.badge(theme.severity_color(severity)),
    )
}

fn verdict_chip(theme: &Theme, verdict: expe_core::Verdict) -> Span<'static> {
    Span::styled(
        format!(" {} ", verdict.label().to_uppercase()),
        theme.badge(theme.verdict_color(verdict)),
    )
}

fn confidence_chip(theme: &Theme, confidence: expe_core::Confidence) -> Span<'static> {
    let color = match confidence {
        expe_core::Confidence::High => theme.good,
        expe_core::Confidence::Medium => theme.warn,
        expe_core::Confidence::Low => theme.muted,
    };
    Span::styled(
        format!(" {} ", confidence.label().to_uppercase()),
        theme.badge(color),
    )
}

fn kv_line(theme: &Theme, label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label:<13}"), theme.muted_style()),
        Span::styled(sanitize(&value.into()), Style::default().fg(theme.text)),
    ])
}

fn clipped_kv(theme: &Theme, label: &str, value: &str, width: usize) -> Line<'static> {
    let label_width = 13;
    let value_width = width.saturating_sub(label_width);
    Line::from(vec![
        Span::styled(format!("{label:<label_width$}"), theme.muted_style()),
        Span::styled(
            clip_ascii(value, value_width, theme.ascii),
            Style::default().fg(theme.text),
        ),
    ])
}

fn format_size(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if size < 1024 {
        return format!("{size} B");
    }
    #[allow(clippy::cast_precision_loss)]
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn format_offset(offset: u64) -> String {
    format!("0x{offset:08X}")
}

fn status_style(theme: &Theme, status: &Status) -> Style {
    match status {
        Status::Ready => Style::default().fg(theme.good),
        Status::Analyzing => Style::default().fg(theme.accent),
        Status::Failed(_) => Style::default().fg(theme.bad),
        Status::Idle => theme.muted_style(),
    }
}

fn selected_marker(theme: &Theme, selected: bool) -> Span<'static> {
    if selected {
        Span::styled("▌", Style::default().fg(theme.accent))
    } else {
        Span::raw(" ")
    }
}

fn filter_bar(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme, title: &str) {
    let block = theme.panel(title);
    let line = if app.input == crate::app::InputMode::Filter {
        Line::from(vec![
            Span::styled("/ ", theme.accent_style()),
            Span::raw(sanitize(&app.filter)),
            Span::styled("▌", theme.accent_style()),
        ])
    } else if app.filter.is_empty() {
        Line::from(Span::styled(
            "press / to filter · Enter to apply",
            theme.muted_style(),
        ))
    } else {
        Line::from(vec![
            Span::styled("filter: ", theme.muted_style()),
            Span::styled(sanitize(&app.filter), Style::default().fg(theme.accent)),
            Span::styled("  (/ edit, Esc clear)", theme.muted_style()),
        ])
    };
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn multiline_value_lines(
    theme: &Theme,
    label: &str,
    value: &str,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let clean = sanitize_multiline(value);
    let max = width.saturating_sub(2).max(8);
    for (index, line) in clean.lines().enumerate() {
        let prefix = if index == 0 {
            format!("{label:<12}")
        } else {
            " ".repeat(12)
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, theme.muted_style()),
            Span::raw(clip(&line, max)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("{label:<12}(empty)"),
            theme.muted_style(),
        )));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn renders_every_screen_and_overlay_without_panicking() {
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new();

        for screen in [
            Screen::Open,
            Screen::Overview,
            Screen::Structure,
            Screen::Strings,
            Screen::Iocs,
            Screen::Findings,
            Screen::Hex,
        ] {
            app.screen = screen;
            app.show_help = false;
            terminal
                .draw(|frame| draw(frame, &mut app))
                .expect("screen should render");
        }

        app.show_help = true;
        terminal
            .draw(|frame| draw(frame, &mut app))
            .expect("help overlay should render");

        app.show_help = false;
        app.set_toast("render smoke test", crate::app::ToastKind::Info);
        terminal
            .draw(|frame| draw(frame, &mut app))
            .expect("toast should render");
    }
}

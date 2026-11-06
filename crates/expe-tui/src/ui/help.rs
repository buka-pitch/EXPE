use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Clear, Paragraph};

use super::{Theme, centered_rect};

pub fn draw(frame: &mut Frame<'_>, area: Rect, theme: &Theme) {
    let width = area.width.clamp(50, 78);
    let height = area.height.clamp(18, 28);
    let popup = centered_rect(area, width, height);

    // Erase whatever was underneath, then paint an opaque card. Without this
    // (and the explicit background on the paragraph below) cells that carry no
    // style fall back to Reset and reveal the screen behind the popup.
    frame.render_widget(Clear, popup);
    let block = theme.panel("HELP · KEYBINDINGS");
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let lines = vec![
        Line::from(Span::styled(
            "NAVIGATION",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("  1–6 / Tab / Shift+Tab", theme.accent_style()),
            Span::styled("  switch views", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  ↑ ↓  j k", theme.accent_style()),
            Span::styled("  move selection", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  PgUp PgDn", theme.accent_style()),
            Span::styled("  jump by 10", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  Home End", theme.accent_style()),
            Span::styled("  first / last", theme.muted_style()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "ACTIONS",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("  /", theme.accent_style()),
            Span::styled("  filter current list", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  Enter / x", theme.accent_style()),
            Span::styled("  jump to hex at offset", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  c", theme.accent_style()),
            Span::styled("  copy value / evidence (OSC52)", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  d", theme.accent_style()),
            Span::styled("  toggle defanged IOC display", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  e", theme.accent_style()),
            Span::styled("  export JSON report", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  r", theme.accent_style()),
            Span::styled("  re-analyze current sample", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  o", theme.accent_style()),
            Span::styled("  open / change sample", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  g", theme.accent_style()),
            Span::styled("  goto hex offset (hex view only)", theme.muted_style()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "GLOBAL",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("  ?  F1", theme.accent_style()),
            Span::styled("  show this help", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  q  Ctrl+C", theme.accent_style()),
            Span::styled("  quit", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  Esc", theme.accent_style()),
            Span::styled(
                "  cancel / close overlay / back to overview",
                theme.muted_style(),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "ENVIRONMENT",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("  NO_COLOR", theme.accent_style()),
            Span::styled("  disable all colours", theme.muted_style()),
        ]),
        Line::from(vec![
            Span::styled("  EXPE_ASCII", theme.accent_style()),
            Span::styled("  ASCII-only borders & icons", theme.muted_style()),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(theme.surface).fg(theme.text))
            .alignment(Alignment::Left)
            .wrap(ratatui::widgets::Wrap { trim: true }),
        inner,
    );
}

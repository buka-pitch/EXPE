use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph};

use super::{Theme, clip_ascii, format_size, status_style, verdict_chip};
use crate::app::{App, Status};

// Both report states build the same (left, right) pair; the match keeps that
// symmetry explicit.
#[allow(clippy::single_match_else)]
pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let block = Block::bordered()
        .border_type(theme.border_type())
        .border_style(theme.border_style())
        .style(Style::default().bg(theme.surface).fg(theme.text));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let right_width = (inner.width / 2).clamp(24, 38);
    let columns =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(right_width)]).split(inner);

    let (left_lines, right_lines) = match &app.report {
        Some(report) => {
            let artifact = &report.artifact;
            let left = Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        "EXPE",
                        Style::default()
                            .fg(theme.accent)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled("  static triage  ", theme.muted_style()),
                    Span::styled(
                        clip_ascii(&artifact.file_name, 40, theme.ascii),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(artifact.format.label(), theme.accent_style()),
                    Span::styled(" · ", theme.muted_style()),
                    Span::styled(artifact.arch.label(), theme.muted_style()),
                    Span::styled(" · ", theme.muted_style()),
                    Span::styled(artifact.kind.label(), theme.muted_style()),
                    Span::styled(" · ", theme.muted_style()),
                    Span::styled(format_size(artifact.size), theme.muted_style()),
                    Span::styled(" · entropy ", theme.muted_style()),
                    Span::styled(
                        format!("{:.2}", artifact.entropy),
                        Style::default().fg(theme.entropy_color(artifact.entropy)),
                    ),
                ]),
            ]);
            let right = Text::from(vec![
                Line::from(vec![
                    Span::raw("RISK "),
                    verdict_chip(theme, report.risk.verdict),
                    Span::styled(
                        format!(" {:>3}", report.risk.score),
                        Style::default()
                            .fg(theme.verdict_color(report.risk.verdict))
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(status_line(app, theme)),
            ]);
            (left, right)
        }
        None => {
            let left = Text::from(vec![
                Line::from(Span::styled(
                    "EXPE",
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    "static binary triage · PE / ELF / Mach-O",
                    theme.muted_style(),
                )),
            ]);
            let right = Text::from(vec![
                Line::from(Span::styled("NO SAMPLE", theme.muted_style())),
                Line::from(status_line(app, theme)),
            ]);
            (left, right)
        }
    };

    frame.render_widget(
        Paragraph::new(left_lines)
            .style(Style::default().bg(theme.surface))
            .alignment(Alignment::Left),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new(right_lines)
            .style(Style::default().bg(theme.surface))
            .alignment(Alignment::Right),
        columns[1],
    );
}

fn status_line<'a>(app: &App, theme: &Theme) -> Vec<Span<'a>> {
    match &app.status {
        Status::Analyzing => vec![
            Span::styled(app.spinner().to_string(), theme.accent_style()),
            Span::styled(
                format!(
                    " {} {}/{}",
                    app.stage.label(),
                    app.stage.position(),
                    expe_engine::Stage::total()
                ),
                theme.accent_style(),
            ),
        ],
        Status::Ready => vec![
            Span::styled("● READY", status_style(theme, &app.status)),
            Span::styled(
                app.report
                    .as_ref()
                    .map_or_else(String::new, |report| format!(" · {} ms", report.timing_ms)),
                theme.muted_style(),
            ),
        ],
        Status::Failed(_) => vec![
            Span::styled("● FAILED", status_style(theme, &app.status)),
            Span::styled(" · Enter retry", theme.muted_style()),
        ],
        Status::Idle => vec![Span::styled("● IDLE", theme.muted_style())],
    }
}

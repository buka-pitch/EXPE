use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;

use super::{Theme, centered_rect, clip_ascii, sanitize};
use crate::app::{App, Status};

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let card_width = area.width.clamp(50, 72);
    let card_height = if app.status.is_analyzing() { 14 } else { 11 };
    let card = centered_rect(area, card_width, card_height);
    let block = theme.panel("EXPE");
    let inner = block.inner(card);
    frame.render_widget(block, card);

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  E X P E",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  static binary triage  ·  PE / ELF / Mach-O",
            theme.muted_style(),
        )),
        Line::from(""),
    ];

    match &app.status {
        Status::Analyzing => {
            lines.push(Line::from(vec![
                Span::styled(app.spinner(), theme.accent_style()),
                Span::raw(" "),
                Span::styled(app.stage.label(), theme.accent_style()),
                Span::styled(
                    format!(" {}/{}", app.stage.position(), expe_engine::Stage::total()),
                    theme.accent_style(),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                clip_ascii(&app.open_path, (inner.width - 4) as usize, theme.ascii),
                theme.muted_style(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "working — the sample is never executed",
                theme.muted_style(),
            )));
        }
        Status::Failed(error) => {
            lines.push(Line::from(Span::styled(
                "Analysis failed",
                theme.badge(theme.bad),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                sanitize(error),
                Style::default().fg(theme.bad),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press Enter to retry or o to open a different sample",
                theme.muted_style(),
            )));
        }
        _ => {
            lines.push(Line::from(Span::styled(
                "  Path",
                Style::default().fg(theme.text),
            )));
            let path_display = if app.open_path.is_empty() {
                Span::styled("  > /path/to/sample.bin", theme.muted_style())
            } else {
                Span::styled(
                    format!(
                        "  > {}",
                        clip_ascii(&app.open_path, (inner.width - 6) as usize, theme.ascii)
                    ),
                    Style::default().fg(theme.text),
                )
            };
            lines.push(Line::from(path_display));
            lines.push(Line::from(""));
            let hints = if app.report.is_some() {
                "Enter analyze · o new file · q quit"
            } else {
                "Enter analyze · q quit"
            };
            lines.push(Line::from(Span::styled(hints, theme.muted_style())));
        }
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(theme.surface))
            .alignment(Alignment::Left),
        inner,
    );
}

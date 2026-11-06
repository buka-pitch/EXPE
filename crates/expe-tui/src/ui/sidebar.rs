use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph};

use super::{Theme, format_size, selected_marker};
use crate::app::{App, Screen};
use crate::sanitize::clip_ascii;

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let block = theme.panel("VIEWS");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let width = inner.width as usize;
    let mut lines = vec![Line::from("")];
    let findings = app.severity_counts();
    let ioc_count = app
        .report
        .as_ref()
        .map_or(0, expe_core::AnalysisReport::ioc_count);

    for (index, screen) in Screen::NAV.iter().enumerate() {
        let selected = app.screen == *screen;
        let count = match screen {
            Screen::Findings => Some(findings.actionable()),
            Screen::Iocs => Some(ioc_count),
            _ => None,
        };
        let label = format!(
            " {} {:<10}{}",
            screen.icon(app.ascii),
            screen.title(),
            count.map_or_else(String::new, |count| format!(" {count}"))
        );
        let style = if selected {
            theme.selected_style()
        } else {
            Style::default().fg(theme.text)
        };
        let mut spans = vec![selected_marker(theme, selected), Span::styled(label, style)];
        if width > 3 {
            spans.push(Span::styled(
                format!(" {}", index + 1),
                if selected {
                    Style::default().fg(theme.accent)
                } else {
                    theme.muted_style()
                },
            ));
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "SAMPLE",
        Style::default()
            .fg(theme.muted)
            .add_modifier(Modifier::BOLD),
    )));
    if let Some(report) = &app.report {
        lines.push(Line::from(Span::styled(
            format!(
                "{} · {}",
                report.artifact.format.label(),
                report.artifact.arch.label()
            ),
            theme.accent_style(),
        )));
        lines.push(Line::from(Span::styled(
            format_size(report.artifact.size),
            theme.muted_style(),
        )));
        lines.push(Line::from(Span::styled(
            format!("{} sections", super::count_sections(report)),
            theme.muted_style(),
        )));
        lines.push(Line::from(Span::styled(
            format!("{} strings", report.strings.total),
            theme.muted_style(),
        )));
        if let Some(path) = &report.artifact.path {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("PATH", theme.muted_style())));
            let clipped = clip_ascii(path, width.saturating_sub(1), theme.ascii);
            lines.push(Line::from(Span::styled(clipped, theme.muted_style())));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "Open a binary to begin",
            theme.muted_style(),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "1-6 jump · Tab cycle",
        theme.muted_style(),
    )));

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().bg(theme.surface))
            .block(Block::default().style(Style::default().bg(theme.surface))),
        inner,
    );
}

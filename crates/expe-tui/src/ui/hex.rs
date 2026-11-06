use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph};

use super::{Theme, format_offset};
use crate::app::{App, InputMode};

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let rows = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
    draw_info(frame, rows[0], app, theme);

    let block = theme.panel("RAW BYTES");
    let inner = block.inner(rows[1]);
    frame.render_widget(block, rows[1]);
    let Some(raw) = &app.raw else {
        frame.render_widget(
            Paragraph::new("Raw bytes are unavailable for this analysis.")
                .style(theme.muted_style())
                .alignment(ratatui::layout::Alignment::Center),
            inner,
        );
        return;
    };
    if raw.is_empty() {
        frame.render_widget(
            Paragraph::new("The sample is empty.").style(theme.muted_style()),
            inner,
        );
        return;
    }

    let bytes_per_line = if inner.width >= 88 {
        16
    } else if inner.width >= 56 {
        8
    } else {
        4
    };
    let line_count = inner.height.max(1) as usize;
    let start = app.hex_offset / bytes_per_line as u64 * bytes_per_line as u64;
    let mark = app.hex_mark;
    let mut lines = Vec::new();
    for index in 0..line_count {
        let offset = start + (index as u64 * bytes_per_line as u64);
        if offset >= raw.len() as u64 {
            break;
        }
        let Ok(start) = usize::try_from(offset) else {
            break;
        };
        let end = start.saturating_add(bytes_per_line).min(raw.len());
        let slice = &raw[start..end];
        let hex = slice
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = slice
            .iter()
            .map(|byte| {
                if (0x20..=0x7E).contains(byte) {
                    char::from(*byte)
                } else {
                    '.'
                }
            })
            .collect();
        let marked =
            mark.is_some_and(|mark| mark >= offset && mark < offset + bytes_per_line as u64);
        let style = if marked {
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text)
        };
        let mut spans = vec![
            Span::styled(format_offset(offset), theme.muted_style()),
            Span::raw("  "),
            Span::styled(format!("{hex:<width$}", width = bytes_per_line * 3), style),
            Span::raw("  "),
            Span::styled(ascii, style),
        ];
        if marked {
            spans.push(Span::styled("  ← selected", theme.accent_style()));
        }
        lines.push(Line::from(spans));
    }

    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().fg(theme.text)),
        inner,
    );
}

fn draw_info(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let block = Block::bordered()
        .border_type(theme.border_type())
        .border_style(theme.border_style())
        .style(Style::default().bg(theme.surface));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let line = if app.input == InputMode::GotoHex {
        Line::from(vec![
            Span::styled("goto offset (hex) > ", theme.accent_style()),
            Span::raw(&app.goto_buf),
            Span::styled("▌", theme.accent_style()),
            Span::styled("  Enter jump · Esc cancel", theme.muted_style()),
        ])
    } else {
        let size = app.raw.as_ref().map_or(0, |raw| raw.len());
        Line::from(vec![
            Span::styled(format_offset(app.hex_offset), theme.accent_style()),
            Span::styled(
                format!("  of {size} bytes  ·  ↑↓ scroll  ·  g goto  ·  Esc overview"),
                theme.muted_style(),
            ),
        ])
    };
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(theme.surface)),
        inner,
    );
}

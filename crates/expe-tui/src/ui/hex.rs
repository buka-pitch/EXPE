use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph};

use super::{Theme, format_offset};
use crate::app::{App, InputMode};

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let rows = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
    let block = theme.panel("RAW BYTES");
    let inner = block.inner(rows[1]);

    let bytes_per_line = bytes_per_line_for(inner.width);
    let line_count = usize::from(inner.height.max(1));
    app.prepare_hex_viewport(bytes_per_line, line_count);

    draw_info(frame, rows[0], app, theme, bytes_per_line);
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

    let line_bytes = u64::try_from(bytes_per_line).unwrap_or(u64::MAX).max(1);
    let raw_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    let start = app.hex_offset / line_bytes * line_bytes;
    let mark = app.hex_mark;
    let mut lines = Vec::new();
    for index in 0..line_count {
        let line_index = u64::try_from(index).unwrap_or(u64::MAX);
        let offset = start.saturating_add(line_index.saturating_mul(line_bytes));
        if offset >= raw_len {
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
            mark.is_some_and(|mark| mark >= offset && mark < offset.saturating_add(line_bytes));
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

/// Pick a byte width that uses most of the available line. Each byte needs
/// roughly four columns (two hex digits, one separator, one ASCII glyph) plus
/// the offset and inter-column padding.
fn bytes_per_line_for(width: u16) -> usize {
    const CANDIDATES: [usize; 9] = [64, 56, 48, 40, 32, 24, 16, 8, 4];
    let width = usize::from(width);
    CANDIDATES
        .into_iter()
        .find(|bytes| width >= bytes.saturating_mul(4).saturating_add(14))
        .unwrap_or(4)
}

fn draw_info(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme, bytes_per_line: usize) {
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
                format!(
                    "  of {size} bytes  ·  {bytes_per_line} B/line  ·  ↑↓/PgUp/PgDn scroll  ·  g goto  ·  Esc overview"
                ),
                theme.muted_style(),
            ),
        ])
    };
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(theme.surface)),
        inner,
    );
}

#[cfg(test)]
mod tests {
    use super::bytes_per_line_for;

    #[test]
    fn hex_line_width_adapts_to_the_viewport() {
        assert_eq!(bytes_per_line_for(45), 4);
        assert_eq!(bytes_per_line_for(46), 8);
        assert_eq!(bytes_per_line_for(78), 16);
        assert_eq!(bytes_per_line_for(142), 32);
        assert_eq!(bytes_per_line_for(206), 48);
        assert_eq!(bytes_per_line_for(270), 64);
    }
}

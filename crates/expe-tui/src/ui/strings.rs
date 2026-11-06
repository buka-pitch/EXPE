use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};

use super::{Theme, clip_ascii, filter_bar, format_offset};
use crate::app::App;
use crate::sanitize::sanitize;

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let rows = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
    filter_bar(frame, rows[0], app, theme, "SEARCH STRINGS");

    let total = app.report.as_ref().map_or(0, |report| report.strings.total);
    let matching = app.filtered_strings().len();
    let title = if app.filter.is_empty() {
        format!("STRINGS · {total}")
    } else {
        format!("STRINGS · {matching}/{total}")
    };
    let block = theme.panel(&title);
    let inner = block.inner(rows[1]);
    frame.render_widget(block, rows[1]);

    let height = inner.height.saturating_sub(1) as usize;
    app.prepare_viewport(height);
    let strings = app.filtered_strings();
    if strings.is_empty() {
        let message = if app.filter.is_empty() {
            "No printable strings were extracted from this sample."
        } else {
            "No strings match the current filter."
        };
        frame.render_widget(
            Paragraph::new(sanitize(message))
                .style(theme.muted_style())
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }

    let start = app.strings_scroll.min(strings.len());
    let visible = strings.iter().skip(start).take(height.max(1));
    let value_width = (inner.width as usize).saturating_sub(26).max(12);
    let rows: Vec<Row<'static>> = visible
        .map(|item| {
            Row::new(vec![
                Cell::from(format_offset(item.offset)),
                Cell::from(item.encoding.label()),
                Cell::from(item.occurrences.to_string()),
                Cell::from(clip_ascii(&item.value, value_width, theme.ascii)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(4),
            Constraint::Fill(1),
        ],
    )
    .header(Row::new(vec!["OFFSET", "ENC", "×", "STRING"]).style(theme.muted_style()))
    .column_spacing(1)
    .row_highlight_style(theme.selected_style())
    .highlight_symbol(if theme.ascii { "> " } else { "▌ " });

    let relative = app.strings_selected.saturating_sub(start);
    let mut state = TableState::default().with_selected(Some(relative));
    frame.render_stateful_widget(table, inner, &mut state);
}

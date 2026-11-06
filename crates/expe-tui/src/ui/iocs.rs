use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};

use super::{Theme, clip_ascii, confidence_chip, filter_bar, format_offset, multiline_value_lines};
use crate::app::App;
use crate::sanitize::sanitize;

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let rows = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
    filter_bar(frame, rows[0], app, theme, "SEARCH INDICATORS");
    let columns = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .spacing(1)
        .split(rows[1]);
    draw_table(frame, columns[0], app, theme);
    draw_detail(frame, columns[1], app, theme);
}

fn draw_table(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let total = app
        .report
        .as_ref()
        .map_or(0, expe_core::AnalysisReport::ioc_count);
    let matching = app.filtered_iocs().len();
    let title = if app.filter.is_empty() {
        format!("INDICATORS · {total}")
    } else {
        format!("INDICATORS · {matching}/{total}")
    };
    let block = theme.panel(&title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let height = inner.height.saturating_sub(1) as usize;
    app.prepare_viewport(height);
    let iocs = app.filtered_iocs();
    if iocs.is_empty() {
        frame.render_widget(
            Paragraph::new("No indicators matched. Try a different filter.")
                .style(theme.muted_style())
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }

    let start = app.iocs_scroll.min(iocs.len());
    let visible = iocs.iter().skip(start).take(height.max(1));
    let value_width = (inner.width as usize).saturating_sub(26).max(10);
    let rows: Vec<Row<'static>> = visible
        .map(|item| {
            let value = if app.defang {
                &item.defanged
            } else {
                &item.value
            };
            let color = theme.confidence_color(item.confidence);
            Row::new(vec![
                Cell::from(item.kind.label()),
                Cell::from(clip_ascii(value, value_width, theme.ascii)),
                Cell::from(Span::styled(
                    item.confidence_rank().to_string(),
                    Style::default().fg(color),
                )),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Fill(1),
            Constraint::Length(4),
        ],
    )
    .header(Row::new(vec!["KIND", "VALUE", "CONF"]).style(theme.muted_style()))
    .column_spacing(1)
    .row_highlight_style(theme.selected_style())
    .highlight_symbol(if theme.ascii { "> " } else { "▌ " });

    let relative = app.iocs_selected.saturating_sub(start);
    let mut state = TableState::default().with_selected(Some(relative));
    frame.render_stateful_widget(table, inner, &mut state);
}

fn draw_detail(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let block = theme.panel("INDICATOR DETAIL");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(item) = app.selected_ioc() else {
        frame.render_widget(
            Paragraph::new("Select an indicator to inspect its sources and offsets.")
                .style(theme.muted_style())
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    };

    let width = inner.width as usize;
    let primary = if app.defang {
        &item.defanged
    } else {
        &item.value
    };
    let mut lines = vec![
        Line::from(vec![
            Span::styled(item.kind.label(), theme.accent_style()),
            Span::raw("  "),
            confidence_chip(theme, item.confidence),
        ]),
        Line::from(""),
    ];
    lines.extend(multiline_value_lines(theme, "VALUE", primary, width));
    if app.defang {
        lines.push(Line::from(Span::styled(
            "raw value hidden while defang mode is on · press d",
            theme.muted_style(),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(format!("{:<13}", "SCOPE"), theme.muted_style()),
        Span::styled(
            item.scope
                .map_or("n/a", expe_core::IpScope::label)
                .to_string(),
            Style::default().fg(theme.text),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled(format!("{:<13}", "OCCURRENCES"), theme.muted_style()),
        Span::styled(
            item.occurrences.to_string(),
            Style::default().fg(theme.text),
        ),
    ]));
    let mut sources = String::new();
    for (index, source) in item.sources.iter().enumerate() {
        if index > 0 {
            sources.push_str(", ");
        }
        sources.push_str(source.label());
    }
    lines.push(Line::from(vec![
        Span::styled(format!("{:<13}", "SOURCES"), theme.muted_style()),
        Span::styled(sources, Style::default().fg(theme.text)),
    ]));
    let offsets = item
        .offsets
        .iter()
        .take(6)
        .map(|offset| format_offset(*offset))
        .collect::<Vec<_>>()
        .join("  ");
    let suffix = if item.offsets.len() > 6 {
        format!("  +{}", item.offsets.len() - 6)
    } else {
        String::new()
    };
    lines.push(Line::from(vec![
        Span::styled(format!("{:<13}", "OFFSETS"), theme.muted_style()),
        Span::styled(
            format!("{offsets}{suffix}"),
            Style::default().fg(theme.text),
        ),
    ]));
    if let Some(rule) = &item.rule_id {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<13}", "RULE"), theme.muted_style()),
            Span::styled(sanitize(rule), Style::default().fg(theme.accent2)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "c copy · Enter/x hex · d defang · / filter",
        theme.muted_style(),
    )));

    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().fg(theme.text))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};

use super::{Theme, clip_ascii, filter_bar, multiline_value_lines, severity_chip};
use crate::app::App;
use crate::sanitize::sanitize;

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let rows = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
    filter_bar(frame, rows[0], app, theme, "SEARCH FINDINGS");
    let columns = Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)])
        .spacing(1)
        .split(rows[1]);
    draw_table(frame, columns[0], app, theme);
    draw_detail(frame, columns[1], app, theme);
}

fn draw_table(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let total = app
        .report
        .as_ref()
        .map_or(0, |report| report.findings.len());
    let matching = app.filtered_findings().len();
    let title = if app.filter.is_empty() {
        format!("FINDINGS · {total}")
    } else {
        format!("FINDINGS · {matching}/{total}")
    };
    let block = theme.panel(&title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let height = inner.height.saturating_sub(1) as usize;
    app.prepare_viewport(height);
    let findings = app.filtered_findings();
    if findings.is_empty() {
        let message = if app.filter.is_empty() {
            "No heuristic findings. The sample looks structurally unremarkable."
        } else {
            "No findings match the current filter."
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

    let start = app.findings_scroll.min(findings.len());
    let visible = findings.iter().skip(start).take(height.max(1));
    let title_width = (inner.width as usize).saturating_sub(28).max(8);
    let rows: Vec<Row<'static>> = visible
        .map(|finding| {
            Row::new(vec![
                Cell::from(severity_chip(theme, finding.severity)),
                Cell::from(clip_ascii(&finding.id, 18, theme.ascii)),
                Cell::from(clip_ascii(&finding.title, title_width, theme.ascii)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Fill(1),
        ],
    )
    .header(Row::new(vec!["SEVERITY", "ID", "TITLE"]).style(theme.muted_style()))
    .column_spacing(1)
    .row_highlight_style(theme.selected_style())
    .highlight_symbol(if theme.ascii { "> " } else { "▌ " });

    let relative = app.findings_selected.saturating_sub(start);
    let mut state = TableState::default().with_selected(Some(relative));
    frame.render_stateful_widget(table, inner, &mut state);
}

fn draw_detail(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let block = theme.panel("FINDING DETAIL");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(finding) = app.selected_finding() else {
        frame.render_widget(
            Paragraph::new("Select a finding to read the evidence and ATT&CK mapping.")
                .style(theme.muted_style())
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    };

    let width = inner.width as usize;
    let mut lines = vec![
        Line::from(severity_chip(theme, finding.severity)),
        Line::from(""),
        Line::from(Span::styled(
            sanitize(&finding.title),
            Style::default()
                .fg(theme.text)
                .add_modifier(ratatui::style::Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(format!("{:<13}", "ID"), theme.muted_style()),
            Span::styled(sanitize(&finding.id), Style::default().fg(theme.accent2)),
        ]),
        Line::from(vec![
            Span::styled(format!("{:<13}", "CATEGORY"), theme.muted_style()),
            Span::styled(finding.category.label(), Style::default().fg(theme.text)),
        ]),
        Line::from(""),
        Line::from(Span::styled("EVIDENCE", theme.muted_style())),
    ];
    lines.extend(multiline_value_lines(theme, "", &finding.evidence, width));
    if !finding.attack.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("ATT&CK", theme.muted_style())));
        for technique in &finding.attack {
            lines.push(Line::from(vec![
                Span::styled("  • ", theme.accent_style()),
                Span::styled(sanitize(technique), Style::default().fg(theme.text)),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "c copy evidence · / filter · e export",
        theme.muted_style(),
    )));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().fg(theme.text))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;

use super::{Theme, clip_ascii, clipped_kv, format_size, kv_line, severity_chip, verdict_chip};
use crate::app::App;

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let Some(report) = &app.report else {
        super::empty_panel(
            frame,
            area,
            theme,
            "OVERVIEW",
            "No analysis loaded. Press o to open a sample.",
        );
        return;
    };

    let rows = Layout::vertical([
        Constraint::Length(6),
        Constraint::Fill(1),
        Constraint::Length(5),
    ])
    .spacing(1)
    .split(area);
    let cards = Layout::horizontal([
        Constraint::Percentage(28),
        Constraint::Percentage(22),
        Constraint::Percentage(25),
        Constraint::Percentage(25),
    ])
    .spacing(1)
    .split(rows[0]);

    // Risk card.
    let risk_color = theme.verdict_color(report.risk.verdict);
    let risk_lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{:>3}", report.risk.score),
                Style::default().fg(risk_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" / 100", theme.muted_style()),
        ]),
        Line::from(verdict_chip(theme, report.risk.verdict)),
        Line::from(Span::styled(
            theme.meter(f64::from(report.risk.score) / 100.0, 18),
            Style::default().fg(risk_color),
        )),
    ];
    card(frame, cards[0], theme, "RISK", risk_lines);

    // Format card.
    let format_lines = vec![
        Line::from(Span::styled(
            report.artifact.format.label(),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(report.artifact.arch.label(), theme.muted_style()),
            Span::styled(" · ", theme.muted_style()),
            Span::styled(report.artifact.kind.label(), theme.muted_style()),
        ]),
        Line::from(Span::styled(
            format_size(report.artifact.size),
            theme.muted_style(),
        )),
        Line::from(vec![
            Span::styled("entropy ", theme.muted_style()),
            Span::styled(
                format!("{:.2}", report.artifact.entropy),
                Style::default().fg(theme.entropy_color(report.artifact.entropy)),
            ),
        ]),
    ];
    card(frame, cards[1], theme, "FORMAT", format_lines);

    // Findings card.
    let counts = app.severity_counts();
    let mut chips = Vec::new();
    for (severity, count) in [
        (expe_core::Severity::Critical, counts.critical),
        (expe_core::Severity::High, counts.high),
        (expe_core::Severity::Medium, counts.medium),
        (expe_core::Severity::Low, counts.low),
    ] {
        if count > 0 {
            chips.push(severity_chip(theme, severity));
            chips.push(Span::raw(" "));
        }
    }
    if chips.is_empty() {
        chips.push(Span::styled("clean", theme.accent_style()));
    }
    let top_category = report
        .risk
        .factors
        .iter()
        .max_by_key(|factor| factor.capped_points)
        .map_or("no contributing category", |factor| factor.category.label());
    let finding_lines = vec![
        Line::from(Span::styled(
            counts.actionable().to_string(),
            Style::default()
                .fg(theme.accent2)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(chips),
        Line::from(Span::styled(
            clip_ascii(top_category, 28, theme.ascii),
            theme.muted_style(),
        )),
    ];
    card(frame, cards[2], theme, "FINDINGS", finding_lines);

    // Indicator card.
    let kinds = app.ioc_kind_counts();
    let mut ioc_line = Vec::new();
    for (index, (kind, count)) in kinds.iter().take(3).enumerate() {
        if index > 0 {
            ioc_line.push(Span::styled("  ", theme.muted_style()));
        }
        ioc_line.push(Span::styled(
            format!("{} ", kind.label()),
            theme.muted_style(),
        ));
        ioc_line.push(Span::styled(
            count.to_string(),
            Style::default().fg(theme.accent),
        ));
    }
    if ioc_line.is_empty() {
        ioc_line.push(Span::styled("none", theme.muted_style()));
    }
    let ioc_lines = vec![
        Line::from(Span::styled(
            report.ioc_count().to_string(),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(ioc_line),
        Line::from(Span::styled(
            format!(
                "{} strings · {} sections",
                report.strings.total,
                super::count_sections(report)
            ),
            theme.muted_style(),
        )),
    ];
    card(frame, cards[3], theme, "INDICATORS", ioc_lines);

    // Findings and entropy panels.
    let middle = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
        .spacing(1)
        .split(rows[1]);
    draw_findings_panel(frame, middle[0], app, theme);
    draw_entropy_panel(frame, middle[1], app, theme);

    // Fingerprint panel.
    let width = rows[2].width.saturating_sub(2) as usize;
    let mut fingerprints = vec![
        clipped_kv(theme, "SHA-256", &report.artifact.hashes.sha256, width),
        clipped_kv(theme, "MD5", &report.artifact.hashes.md5, width),
    ];
    if let Some(imphash) = &report.artifact.hashes.imphash {
        fingerprints.push(clipped_kv(theme, "IMPHASH", imphash, width));
    } else {
        fingerprints.push(kv_line(
            theme,
            "RULESET",
            format!(
                "{} · schema {} · {} ms",
                report.tool.ruleset_version, report.schema_version, report.timing_ms
            ),
        ));
    }
    frame.render_widget(
        Paragraph::new(Text::from(fingerprints)).block(theme.panel("FINGERPRINT")),
        rows[2],
    );
}

fn card(frame: &mut Frame<'_>, area: Rect, theme: &Theme, title: &str, lines: Vec<Line<'static>>) {
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .style(Style::default().fg(theme.text))
            .block(theme.panel(title)),
        area,
    );
}

fn draw_findings_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let Some(report) = &app.report else {
        return;
    };
    let block = theme.panel(&format!("TOP FINDINGS · {}", report.findings.len()));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let max = inner.height as usize;
    let mut lines = Vec::new();
    for finding in report.sorted_findings().into_iter().take(max) {
        lines.push(Line::from(vec![
            severity_chip(theme, finding.severity),
            Span::raw(" "),
            Span::styled(
                clip_ascii(
                    &finding.title,
                    inner.width.saturating_sub(18) as usize,
                    theme.ascii,
                ),
                Style::default().fg(theme.text),
            ),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No heuristic findings",
            theme.accent_style(),
        )));
        lines.push(Line::from(Span::styled(
            "The sample looks structurally unremarkable.",
            theme.muted_style(),
        )));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().fg(theme.text)),
        inner,
    );
}

fn draw_entropy_panel(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    if app.report.is_none() {
        return;
    }
    let block = theme.panel("SECTION ENTROPY");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines = Vec::new();
    let sections = app.sections();
    let max = inner.height as usize;
    let bar_width = (inner.width as usize).saturating_sub(24).clamp(5, 12);
    for section in sections.iter().take(max) {
        let color = theme.entropy_color(section.entropy);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<12}", clip_ascii(&section.name, 12, theme.ascii)),
                Style::default().fg(theme.text),
            ),
            Span::styled(
                theme.meter(section.entropy / 8.0, bar_width),
                Style::default().fg(color),
            ),
            Span::styled(
                format!(" {:.2}", section.entropy),
                Style::default().fg(color),
            ),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No section table for this format.",
            theme.muted_style(),
        )));
    }
    frame.render_widget(
        Paragraph::new(Text::from(lines)).style(Style::default().fg(theme.text)),
        inner,
    );
}

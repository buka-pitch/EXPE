use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};

use super::{Theme, clip_ascii, kv_line};
use crate::app::App;
use crate::sanitize::sanitize;

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let columns = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)])
        .spacing(1)
        .split(area);
    draw_sections(frame, columns[0], app, theme);
    draw_details(frame, columns[1], app, theme);
}

fn draw_sections(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: &Theme) {
    let block = theme.panel(&format!("SECTIONS · {}", app.sections().len()));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let height = inner.height.saturating_sub(1) as usize;
    app.prepare_viewport(height);
    let sections = app.filtered_sections();
    if sections.is_empty() {
        let message = if app.filter.is_empty() {
            "No section metadata was parsed for this format."
        } else {
            "No sections match the current filter."
        };
        frame.render_widget(
            Paragraph::new(sanitize(message))
                .style(theme.muted_style())
                .alignment(ratatui::layout::Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }

    let start = app.structure_scroll.min(sections.len());
    let visible = sections.iter().skip(start).take(height.max(1));
    let name_width = (inner.width as usize * 28 / 100).clamp(8, 22);
    let rows: Vec<Row<'static>> = visible
        .map(|section| {
            let entropy_color = theme.entropy_color(section.entropy);
            Row::new(vec![
                Cell::from(clip_ascii(&section.name, name_width, theme.ascii)),
                Cell::from(format!("0x{:X}", section.virtual_address)),
                Cell::from(format!("0x{:X}+{}", section.raw_offset, section.raw_size)),
                Cell::from(Span::styled(
                    format!("{:.2}", section.entropy),
                    Style::default().fg(entropy_color),
                )),
                Cell::from(section.permissions.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Fill(2),
            Constraint::Length(11),
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(4),
        ],
    )
    .header(Row::new(vec!["NAME", "VIRTUAL", "RAW", "ENTROPY", "PERM"]).style(theme.muted_style()))
    .column_spacing(1)
    .row_highlight_style(theme.selected_style())
    .highlight_symbol(if theme.ascii { "> " } else { "▌ " });

    let relative = app.structure_selected.saturating_sub(start);
    let mut state = TableState::default().with_selected(Some(relative));
    frame.render_stateful_widget(table, inner, &mut state);
}

fn draw_details(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let Some(report) = &app.report else {
        return;
    };
    let rows = Layout::vertical([Constraint::Fill(1), Constraint::Length(8)])
        .spacing(1)
        .split(area);
    let mut lines = Vec::new();
    match &report.structure {
        expe_core::Structure::Pe(info) => {
            lines.push(kv_line(theme, "MACHINE", &info.machine));
            lines.push(kv_line(theme, "SUBSYSTEM", &info.subsystem));
            lines.push(kv_line(theme, "ENTRY", format!("0x{:X}", info.entry_point)));
            lines.push(kv_line(
                theme,
                "IMAGE BASE",
                format!("0x{:X}", info.image_base),
            ));
            lines.push(kv_line(
                theme,
                "TIMESTAMP",
                info.timestamp_iso
                    .clone()
                    .unwrap_or_else(|| info.timestamp.to_string()),
            ));
            lines.push(kv_line(theme, "SIGNED", yes_no(info.is_signed)));
            lines.push(kv_line(theme, ".NET", yes_no(info.is_dotnet)));
            lines.push(kv_line(theme, "RICH", yes_no(info.has_rich_header)));
            lines.push(kv_line(
                theme,
                "TLS CALLBACKS",
                info.tls_callbacks.to_string(),
            ));
            if let Some(pdb) = &info.debug_pdb {
                lines.push(kv_line(theme, "PDB", pdb));
            }
            if let Some(overlay) = &info.overlay {
                lines.push(kv_line(
                    theme,
                    "OVERLAY",
                    format!(
                        "0x{:X} · {} bytes · {:.2}{}",
                        overlay.offset,
                        overlay.size,
                        overlay.entropy,
                        if overlay.embedded.is_empty() {
                            String::new()
                        } else {
                            format!(" · embedded {}", overlay.embedded.join(", "))
                        }
                    ),
                ));
            }
            if let Some(imphash) = &info.imphash {
                lines.push(kv_line(theme, "IMPHASH", imphash));
            }
        }
        expe_core::Structure::Elf(info) => {
            lines.push(kv_line(theme, "CLASS", &info.class));
            lines.push(kv_line(theme, "ENDIAN", &info.endianness));
            lines.push(kv_line(theme, "KIND", &info.kind));
            lines.push(kv_line(theme, "MACHINE", &info.machine));
            lines.push(kv_line(theme, "ENTRY", format!("0x{:X}", info.entry_point)));
            lines.push(kv_line(theme, "STATIC", yes_no(info.is_static)));
            lines.push(kv_line(theme, "STRIPPED", yes_no(info.is_stripped)));
            if let Some(interpreter) = &info.interpreter {
                lines.push(kv_line(theme, "INTERPRETER", interpreter));
            }
            if let Some(build_id) = &info.build_id {
                lines.push(kv_line(theme, "BUILD ID", build_id));
            }
            if !info.rpaths.is_empty() {
                lines.push(kv_line(theme, "RPATH", info.rpaths.join(", ")));
            }
            if !info.runpaths.is_empty() {
                lines.push(kv_line(theme, "RUNPATH", info.runpaths.join(", ")));
            }
        }
        expe_core::Structure::MachO(info) => {
            lines.push(kv_line(theme, "CPU", &info.cpu));
            lines.push(kv_line(theme, "TYPE", &info.file_type));
            lines.push(kv_line(theme, "64-BIT", yes_no(info.is_64)));
            lines.push(kv_line(theme, "ENTRY", format!("0x{:X}", info.entry_point)));
            lines.push(kv_line(theme, "SEGMENTS", info.segments.len().to_string()));
            lines.push(kv_line(
                theme,
                "LIBRARIES",
                info.libraries.len().to_string(),
            ));
        }
        expe_core::Structure::Unavailable => {
            lines.push(Line::from(Span::styled(
                "No normalized structure is available.",
                theme.muted_style(),
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press x or Enter on a string/IOC to jump to raw bytes.",
        theme.muted_style(),
    )));
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: true })
            .block(theme.panel("METADATA")),
        rows[0],
    );

    let import_lines = import_lines(report, theme, rows[1].height.saturating_sub(2) as usize);
    frame.render_widget(
        Paragraph::new(Text::from(import_lines)).block(theme.panel("IMPORTS / LIBRARIES")),
        rows[1],
    );
}

fn import_lines(
    report: &expe_core::AnalysisReport,
    theme: &Theme,
    max: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &report.structure {
        expe_core::Structure::Pe(info) => {
            for library in info.imports.iter().take(max) {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{:<20}", clip_ascii(&library.dll, 20, theme.ascii)),
                        Style::default().fg(theme.accent),
                    ),
                    Span::styled(
                        format!("{} fn", library.functions.len()),
                        theme.muted_style(),
                    ),
                ]));
            }
        }
        expe_core::Structure::Elf(info) => {
            for library in info.libraries.iter().take(max) {
                lines.push(Line::from(Span::styled(
                    clip_ascii(library, 40, theme.ascii),
                    theme.muted_style(),
                )));
            }
        }
        expe_core::Structure::MachO(info) => {
            for library in info.libraries.iter().take(max) {
                lines.push(Line::from(Span::styled(
                    clip_ascii(library, 40, theme.ascii),
                    theme.muted_style(),
                )));
            }
        }
        expe_core::Structure::Unavailable => {}
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No imports or libraries parsed.",
            theme.muted_style(),
        )));
    }
    lines
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

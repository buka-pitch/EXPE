use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use super::{Theme, clip_ascii};
use crate::app::{App, InputMode, Screen, Status};

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    frame.render_widget(
        Block::default().style(Style::default().bg(theme.surface).fg(theme.muted)),
        area,
    );
    let columns = Layout::horizontal([Constraint::Fill(1), Constraint::Length(30)]).split(area);

    let hints = hints_for(app);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" ", theme.muted_style()),
            Span::styled(
                clip_ascii(
                    &hints,
                    columns[0].width.saturating_sub(2) as usize,
                    theme.ascii,
                ),
                theme.muted_style(),
            ),
        ]))
        .style(Style::default().bg(theme.surface)),
        columns[0],
    );

    let right = if app.status == Status::Analyzing {
        format!("{} {}  Esc cancel", app.spinner(), app.stage.position())
    } else if app.input == InputMode::Filter {
        "Enter apply · Esc clear".to_string()
    } else {
        "? help  ·  q quit".to_string()
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{right} "),
            theme.muted_style(),
        )))
        .style(Style::default().bg(theme.surface)),
        columns[1],
    );
}

fn hints_for(app: &App) -> String {
    if app.status == Status::Analyzing {
        return "analyzing safely in a worker · the sample is never executed".to_string();
    }
    match app.screen {
        Screen::Open => "Enter analyze · Esc quit · Ctrl+U clear".to_string(),
        Screen::Overview => "1-6 sections · e export JSON · r re-analyze · o open".to_string(),
        Screen::Structure => "↑↓/jk move · / filter · Enter hex · e export".to_string(),
        Screen::Strings => "↑↓/jk move · / filter · Enter/x hex · c copy".to_string(),
        Screen::Iocs => "↑↓/jk move · / filter · Enter/x hex · c copy · d defang".to_string(),
        Screen::Findings => "↑↓/jk move · / filter · c copy · e export".to_string(),
        Screen::Hex => "↑↓ scroll · PgUp/PgDn · g goto offset · Esc overview".to_string(),
    }
}

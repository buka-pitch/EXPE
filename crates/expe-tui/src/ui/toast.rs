use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Paragraph};

use super::{Theme, clip_ascii, sanitize};
use crate::app::{App, ToastKind};

pub fn draw(frame: &mut Frame<'_>, area: Rect, app: &App, theme: &Theme) {
    let Some(toast) = &app.toast else {
        return;
    };
    let width = area.width.clamp(20, 60);
    let height = 3u16;
    let vertical = Layout::vertical([Constraint::Fill(1), Constraint::Length(height)]).split(area);
    let bottom = vertical[1];
    let horizontal =
        Layout::horizontal([Constraint::Fill(1), Constraint::Length(width)]).split(bottom);
    let toast_area = horizontal[1];

    let (bg, icon) = match toast.kind {
        ToastKind::Good => (theme.good, "✓"),
        ToastKind::Warn => (theme.warn, "⚠"),
        ToastKind::Error => (theme.bad, "✕"),
        ToastKind::Info => (theme.accent, "i"),
    };
    let icon = if theme.ascii { "*" } else { icon };

    let text = sanitize(&toast.text);
    let block = Block::bordered()
        .border_type(theme.border_type())
        .border_style(Style::default().fg(bg))
        .style(Style::default().bg(theme.surface).fg(theme.text));
    let inner = block.inner(toast_area);
    frame.render_widget(block, toast_area);

    let line = Line::from(vec![
        Span::styled(
            format!(" {icon} "),
            Style::default().fg(bg).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            clip_ascii(&text, (inner.width as usize).saturating_sub(4), theme.ascii),
            Style::default().fg(theme.text),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(Text::from(line))
            .style(Style::default().bg(theme.surface))
            .alignment(Alignment::Left),
        inner,
    );
}

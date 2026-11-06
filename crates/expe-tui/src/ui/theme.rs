use expe_core::{Severity, Verdict};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, BorderType};

#[derive(Debug, Clone)]
pub struct Theme {
    pub color: bool,
    pub ascii: bool,
    pub bg: Color,
    pub surface: Color,
    pub text: Color,
    pub muted: Color,
    pub accent: Color,
    pub accent2: Color,
    pub good: Color,
    pub warn: Color,
    pub bad: Color,
    pub critical: Color,
    pub border: Color,
    pub selection: Color,
}

impl Default for Theme {
    fn default() -> Self {
        let color = std::env::var_os("NO_COLOR").is_none();
        let ascii = std::env::var_os("EXPE_ASCII").is_some();
        if color {
            Self {
                color,
                ascii,
                bg: Color::Rgb(11, 13, 19),
                surface: Color::Rgb(20, 24, 33),
                text: Color::Rgb(226, 232, 240),
                muted: Color::Rgb(122, 134, 156),
                accent: Color::Rgb(94, 234, 212),
                accent2: Color::Rgb(167, 139, 250),
                good: Color::Rgb(74, 222, 128),
                warn: Color::Rgb(251, 191, 36),
                bad: Color::Rgb(248, 113, 113),
                critical: Color::Rgb(244, 63, 94),
                border: Color::Rgb(48, 58, 76),
                selection: Color::Rgb(30, 41, 59),
            }
        } else {
            Self {
                color,
                ascii,
                bg: Color::Reset,
                surface: Color::Reset,
                text: Color::Reset,
                muted: Color::Reset,
                accent: Color::Reset,
                accent2: Color::Reset,
                good: Color::Reset,
                warn: Color::Reset,
                bad: Color::Reset,
                critical: Color::Reset,
                border: Color::Reset,
                selection: Color::Reset,
            }
        }
    }
}

impl Theme {
    pub fn panel(&self, title: &str) -> Block<'static> {
        let title_style = if self.color {
            Style::default()
                .fg(self.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };
        Block::bordered()
            .border_type(self.border_type())
            .border_style(self.border_style())
            .style(Style::default().bg(self.surface).fg(self.text))
            .title(ratatui::text::Line::from(ratatui::text::Span::styled(
                format!(" {title} "),
                title_style,
            )))
    }

    pub fn border_type(&self) -> BorderType {
        if self.ascii {
            BorderType::Plain
        } else {
            BorderType::Rounded
        }
    }

    pub fn border_style(&self) -> Style {
        Style::default().fg(if self.color {
            self.border
        } else {
            Color::Reset
        })
    }

    pub fn base(&self) -> Style {
        Style::default().bg(self.bg).fg(self.text)
    }

    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.muted)
    }

    pub fn accent_style(&self) -> Style {
        if self.color {
            Style::default()
                .fg(self.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    pub fn selected_style(&self) -> Style {
        if self.color {
            Style::default().bg(self.selection).fg(self.text)
        } else {
            Style::default().add_modifier(Modifier::REVERSED)
        }
    }

    pub fn badge(&self, color: Color) -> Style {
        if self.color {
            Style::default()
                .fg(self.bg)
                .bg(color)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    pub fn severity_color(&self, severity: Severity) -> Color {
        if !self.color {
            return Color::Reset;
        }
        match severity {
            Severity::Info => self.muted,
            Severity::Low => self.accent,
            Severity::Medium => self.warn,
            Severity::High => self.bad,
            Severity::Critical => self.critical,
        }
    }

    pub fn verdict_color(&self, verdict: Verdict) -> Color {
        if !self.color {
            return Color::Reset;
        }
        match verdict {
            Verdict::Low => self.good,
            Verdict::Elevated => self.warn,
            Verdict::Suspicious => self.bad,
            Verdict::High => self.critical,
        }
    }

    pub fn entropy_color(&self, entropy: f64) -> Color {
        if !self.color {
            return Color::Reset;
        }
        if entropy >= 7.2 {
            self.bad
        } else if entropy >= 6.0 {
            self.warn
        } else {
            self.good
        }
    }

    pub fn confidence_color(&self, confidence: expe_core::Confidence) -> Color {
        if !self.color {
            return Color::Reset;
        }
        match confidence {
            expe_core::Confidence::High => self.good,
            expe_core::Confidence::Medium => self.warn,
            expe_core::Confidence::Low => self.muted,
        }
    }

    pub fn meter(&self, value: f64, width: usize) -> String {
        let clamped = value.clamp(0.0, 1.0);
        let filled = (clamped * width as f64).round() as usize;
        let (full, empty) = if self.ascii {
            ('#', '-')
        } else {
            ('█', '░')
        };
        format!(
            "{}{}",
            full.to_string().repeat(filled),
            empty.to_string().repeat(width.saturating_sub(filled))
        )
    }
}

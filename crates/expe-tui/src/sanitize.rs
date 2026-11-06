//! Terminal-safe text for every value that originates in a sample.
//!
//! The TUI renders attacker-controlled strings, paths, section names and IOC
//! values. Escape sequences, bidi controls and control characters are stripped
//! or replaced before they reach `ratatui`, so a sample cannot move the cursor,
//! retitle the terminal, or spoof the interface.

const REPLACEMENT: char = '\u{FFFD}';

/// Neutralize control and direction-changing characters while keeping printable
/// Unicode. Tabs become single spaces; newlines are preserved only when the
/// caller explicitly asks for multiline text.
#[must_use]
pub fn sanitize(input: &str) -> String {
    sanitize_with(input, false)
}

/// Like [`sanitize`] but keeps `\n` for wrapped detail panes.
#[must_use]
pub fn sanitize_multiline(input: &str) -> String {
    sanitize_with(input, true)
}

fn sanitize_with(input: &str, multiline: bool) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\n' if multiline => out.push('\n'),
            '\n' | '\r' | '\t' | '\u{7}' | '\u{8}' | '\u{b}' | '\u{c}' => out.push(' '),
            '\u{1b}' => {
                // Drop the whole CSI/OSC sequence instead of leaving it visible.
                if chars.peek() == Some(&'[') {
                    let _ = chars.next();
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                } else if chars.peek() == Some(&']') {
                    let _ = chars.next();
                    for next in chars.by_ref() {
                        if next == '\u{7}' {
                            break;
                        }
                    }
                }
            }
            ch if ch.is_control() => out.push(REPLACEMENT),
            ch if is_bidi_control(ch) => out.push(REPLACEMENT),
            ch => out.push(ch),
        }
    }
    out
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch as u32,
        0x061C
            | 0x200E
            | 0x200F
            | 0x202A..=0x202E
            | 0x2066..=0x2069
            | 0xFEFF
            | 0xE000..=0xF8FF
    )
}

/// Clip to a character budget after sanitizing. Uses an ASCII marker when the
/// terminal has requested ASCII-only output.
#[must_use]
pub fn clip(input: &str, width: usize) -> String {
    clip_with_marker(input, width, false)
}

#[must_use]
pub fn clip_ascii(input: &str, width: usize, ascii: bool) -> String {
    clip_with_marker(input, width, ascii)
}

fn clip_with_marker(input: &str, width: usize, ascii: bool) -> String {
    if width == 0 {
        return String::new();
    }
    let clean = sanitize(input);
    if clean.chars().count() <= width {
        return clean;
    }
    let marker = if ascii { "..." } else { "…" };
    let marker_len = marker.chars().count();
    if width <= marker_len {
        return marker.chars().take(width).collect();
    }
    let mut out: String = clean.chars().take(width - marker_len).collect();
    out.push_str(marker);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_sequences() {
        assert_eq!(sanitize("safe\u{1b}[31mred\u{1b}[0m"), "safered");
        assert_eq!(sanitize("title\u{1b}]0;pwned\u{7}ok"), "titleok");
    }

    #[test]
    fn neutralizes_bidi_and_controls() {
        assert_eq!(sanitize("a\u{202E}b\u{7}c"), format!("a{REPLACEMENT}b c"));
        assert_eq!(sanitize("line1\nline2"), "line1 line2");
        assert_eq!(sanitize_multiline("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn clips_without_splitting_chars() {
        assert_eq!(clip("abcdef", 4), "abc…");
        assert_eq!(clip_ascii("abcdef", 5, true), "ab...");
        assert_eq!(clip("abc", 10), "abc");
        assert_eq!(clip("abcdef", 0), "");
    }
}

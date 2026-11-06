/// Neutralize terminal control sequences and bidi overrides in target-derived
/// text. Malware strings frequently contain ESC/OSC payloads and RTL overrides
/// designed to spoof analyst terminals; JSON keeps the raw value, text output never
/// emits raw control characters.
#[must_use]
pub fn sanitize(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' | '\r' | '\t' => out.push(' '),
            '\u{1b}' | '\u{9b}' | '\u{9d}' | '\u{90}' => out.push('?'),
            '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{feff}' => out.push('?'),
            ch if ch.is_control() => out.push('?'),
            ch => out.push(ch),
        }
    }
    out
}

/// Truncate on a character boundary and append an ellipsis.
#[must_use]
pub fn truncate(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let sanitized = sanitize(value);
    if sanitized.chars().count() <= width {
        return sanitized;
    }
    let mut out: String = sanitized.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_escapes_and_bidi() {
        let hostile = "evil\x1b]8;;http://x\x07.test\u{202e}gnp.exe";
        let clean = sanitize(hostile);
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\u{202e}'));
        assert!(clean.contains("evil"));
    }

    #[test]
    fn flattens_newlines() {
        assert_eq!(sanitize("a\nb\tc\0"), "a b c?");
    }

    #[test]
    fn truncates_on_char_boundary() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
    }
}

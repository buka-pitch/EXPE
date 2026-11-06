use std::collections::HashMap;

use expe_core::{ExtractedString, Limits, StringEncoding, StringsSummary};

/// Result of a string scan. Items are always retained in memory for IOC
/// extraction; the report decides whether to serialize them.
#[derive(Debug, Clone, Default)]
pub struct StringScan {
    pub items: Vec<ExtractedString>,
    pub truncated: bool,
    pub scanned_bytes: u64,
}

impl StringScan {
    #[must_use]
    pub fn summary(&self, include_items: bool) -> StringsSummary {
        let ascii = self
            .items
            .iter()
            .filter(|s| s.encoding == StringEncoding::Ascii)
            .count();
        StringsSummary {
            total: self.items.len(),
            ascii,
            utf16le: self.items.len() - ascii,
            truncated: self.truncated,
            items: if include_items {
                self.items.clone()
            } else {
                Vec::new()
            },
        }
    }
}

#[derive(Default)]
struct Deduper {
    index: HashMap<String, usize>,
    items: Vec<ExtractedString>,
    max: usize,
    truncated: bool,
}

impl Deduper {
    fn push(&mut self, value: &str, offset: u64, encoding: StringEncoding, truncated: bool) {
        if self.items.len() >= self.max {
            self.truncated = true;
            return;
        }
        let key = format!("{}\u{1f}{value}", encoding.label());
        if let Some(&existing) = self.index.get(&key) {
            self.items[existing].occurrences = self.items[existing].occurrences.saturating_add(1);
            self.items[existing].truncated |= truncated;
            return;
        }
        self.index.insert(key, self.items.len());
        self.items.push(ExtractedString {
            value: value.to_string(),
            offset,
            encoding,
            occurrences: 1,
            truncated,
        });
    }
}

#[must_use]
pub fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x09 | 0x0a | 0x0d | 0x20..=0x7e)
}

/// Scan ASCII and UTF-16LE printable runs. Offsets always refer to the original
/// file, and values are de-duplicated with occurrence counts.
#[must_use]
pub fn scan(bytes: &[u8], limits: &Limits) -> StringScan {
    let scan_len = usize::try_from(limits.max_scan_bytes)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let data = &bytes[..scan_len];
    let min_len = limits.min_string_len.max(1);
    let max_len = limits.max_string_len.max(min_len);
    let mut deduper = Deduper {
        max: limits.max_strings,
        ..Deduper::default()
    };

    scan_ascii(data, min_len, max_len, &mut deduper);
    scan_utf16le(data, min_len, max_len, &mut deduper);

    StringScan {
        items: deduper.items,
        truncated: deduper.truncated,
        scanned_bytes: scan_len as u64,
    }
}

fn scan_ascii(data: &[u8], min_len: usize, max_len: usize, out: &mut Deduper) {
    let mut start: Option<usize> = None;
    let mut len = 0_usize;
    let mut truncated = false;

    for (idx, &byte) in data.iter().enumerate() {
        if is_printable(byte) {
            if start.is_none() {
                start = Some(idx);
            }
            if len < max_len {
                len += 1;
            } else {
                truncated = true;
            }
        } else if let Some(begin) = start.take() {
            if len >= min_len {
                let end = begin.saturating_add(len);
                if let Some(slice) = data.get(begin..end) {
                    let value = String::from_utf8_lossy(slice);
                    out.push(&value, begin as u64, StringEncoding::Ascii, truncated);
                }
            }
            len = 0;
            truncated = false;
        }
    }

    if let Some(begin) = start
        && len >= min_len
    {
        let end = begin.saturating_add(len);
        if let Some(slice) = data.get(begin..end) {
            let value = String::from_utf8_lossy(slice);
            out.push(&value, begin as u64, StringEncoding::Ascii, truncated);
        }
    }
}

fn scan_utf16le(data: &[u8], min_len: usize, max_len: usize, out: &mut Deduper) {
    let mut idx = 0_usize;
    while idx + 1 < data.len() {
        if is_printable(data[idx]) && data[idx + 1] == 0 {
            let begin = idx;
            let mut len = 0_usize;
            let mut truncated = false;
            let mut value = String::with_capacity(min_len);
            while idx + 1 < data.len() && is_printable(data[idx]) && data[idx + 1] == 0 {
                if len < max_len {
                    value.push(char::from(data[idx]));
                    len += 1;
                } else {
                    truncated = true;
                }
                idx += 2;
            }
            if len >= min_len {
                out.push(&value, begin as u64, StringEncoding::Utf16Le, truncated);
            }
        } else {
            idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits::default()
    }

    #[test]
    fn ascii_offsets_and_dedup() {
        let data = b"\x00\x00hello world\x00hello\x00";
        let scan = scan(data, &limits());
        let hello = scan
            .items
            .iter()
            .find(|s| s.value == "hello world")
            .unwrap();
        assert_eq!(hello.offset, 2);
        let second = scan.items.iter().find(|s| s.value == "hello").unwrap();
        assert_eq!(second.offset, 14);
    }

    #[test]
    fn repeated_values_are_deduped() {
        let scan = scan(b"hello\x00hello\x00hello\x00", &limits());
        let hello = scan.items.iter().find(|s| s.value == "hello").unwrap();
        assert_eq!(hello.offset, 0);
        assert_eq!(hello.occurrences, 3);
    }

    #[test]
    fn utf16_is_detected() {
        let mut data = Vec::new();
        for ch in "http://evil.test".bytes() {
            data.push(ch);
            data.push(0);
        }
        let scan = scan(&data, &limits());
        assert!(scan.items.iter().any(|s| s.value == "http://evil.test"));
        assert!(
            scan.items
                .iter()
                .any(|s| s.encoding == StringEncoding::Utf16Le)
        );
    }

    #[test]
    fn min_length_filters() {
        let mut limits = limits();
        limits.min_string_len = 5;
        let scan = scan(b"abc\x00abcde", &limits);
        assert!(scan.items.iter().any(|s| s.value == "abcde"));
        assert!(!scan.items.iter().any(|s| s.value == "abc"));
    }

    #[test]
    fn max_strings_sets_truncation() {
        let mut limits = limits();
        limits.max_strings = 2;
        let scan = scan(b"aaaa\x00bbbb\x00cccc\x00dddd\x00", &limits);
        assert_eq!(scan.items.len(), 2);
        assert!(scan.truncated);
    }

    #[test]
    fn long_runs_are_truncated() {
        let mut limits = limits();
        limits.max_string_len = 8;
        let scan = scan(b"AAAAAAAAAAAAAAAAAAAA\x00", &limits);
        let item = &scan.items[0];
        assert_eq!(item.value.len(), 8);
        assert!(item.truncated);
    }
}

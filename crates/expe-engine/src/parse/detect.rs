use expe_core::Format;

#[must_use]
pub fn detect_format(bytes: &[u8]) -> Format {
    if bytes.starts_with(b"MZ") {
        return Format::Pe;
    }
    if bytes.starts_with(b"\x7fELF") {
        return Format::Elf;
    }
    if is_macho(bytes) {
        return Format::MachO;
    }
    if archive_kind(bytes).is_some() {
        return Format::Archive;
    }
    Format::Unknown
}

// Six independent magic values are clearer listed one per line.
#[allow(clippy::unnested_or_patterns)]
fn is_macho(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
        )
    )
}

#[must_use]
pub fn archive_kind(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        Some("zip")
    } else if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        Some("7z")
    } else if bytes.starts_with(b"Rar!\x1a\x07") {
        Some("rar")
    } else if bytes.starts_with(b"\x1f\x8b") {
        Some("gzip")
    } else if bytes.starts_with(b"BZh") {
        Some("bzip2")
    } else if bytes.starts_with(b"\xfd7zXZ\x00") {
        Some("xz")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_magics() {
        assert_eq!(detect_format(b"MZ\x90\x00"), Format::Pe);
        assert_eq!(detect_format(b"\x7fELF\x02\x01"), Format::Elf);
        assert_eq!(detect_format(b"\xcf\xfa\xed\xfe"), Format::MachO);
        assert_eq!(detect_format(b"PK\x03\x04"), Format::Archive);
        assert_eq!(detect_format(b"hello"), Format::Unknown);
        assert_eq!(detect_format(b""), Format::Unknown);
    }

    #[test]
    fn archive_names() {
        assert_eq!(archive_kind(b"PK\x03\x04"), Some("zip"));
        assert_eq!(archive_kind(b"7z\xbc\xaf\x27\x1c"), Some("7z"));
        assert_eq!(archive_kind(b"Rar!\x1a\x07\x00"), Some("rar"));
    }
}

//! Deterministic synthetic fixtures. No real malware is stored in this repository.

use std::fmt::Write as _;

const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const OPTIONAL_HEADER_SIZE: usize = 0xF0;
const HEADERS_SIZE: u32 = 0x200;

pub const CHARACTERISTICS_CODE_EXECUTE_READ: u32 = 0x6000_0020;
pub const CHARACTERISTICS_READ_WRITE: u32 = 0xC000_0040;
pub const CHARACTERISTICS_READ_WRITE_EXECUTE: u32 = 0xE000_0020;
pub const CHARACTERISTICS_READ_ONLY: u32 = 0x4000_0040;

#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub data: Vec<u8>,
    pub characteristics: u32,
}

#[derive(Debug, Clone)]
pub struct PeBuilder {
    sections: Vec<PeSection>,
    timestamp: u32,
    entry_point: Option<u32>,
    overlay: Vec<u8>,
    subsystem: u16,
    dll: bool,
}

impl Default for PeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PeBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
            timestamp: 1_700_000_000,
            entry_point: None,
            overlay: Vec::new(),
            subsystem: 3,
            dll: false,
        }
    }

    #[must_use]
    pub fn section(mut self, name: &str, data: Vec<u8>) -> Self {
        self.sections.push(PeSection {
            name: name.to_string(),
            data,
            characteristics: CHARACTERISTICS_CODE_EXECUTE_READ,
        });
        self
    }

    #[must_use]
    pub fn section_with_flags(mut self, name: &str, data: Vec<u8>, characteristics: u32) -> Self {
        self.sections.push(PeSection {
            name: name.to_string(),
            data,
            characteristics,
        });
        self
    }

    #[must_use]
    pub fn timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = timestamp;
        self
    }

    #[must_use]
    pub fn entry_point(mut self, entry: u32) -> Self {
        self.entry_point = Some(entry);
        self
    }

    #[must_use]
    pub fn overlay(mut self, overlay: Vec<u8>) -> Self {
        self.overlay = overlay;
        self
    }

    #[must_use]
    pub fn subsystem(mut self, subsystem: u16) -> Self {
        self.subsystem = subsystem;
        self
    }

    #[must_use]
    pub fn dll(mut self, dll: bool) -> Self {
        self.dll = dll;
        self
    }

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let sections = if self.sections.is_empty() {
            vec![PeSection {
                name: ".text".to_string(),
                data: vec![0x90; 512],
                characteristics: CHARACTERISTICS_CODE_EXECUTE_READ,
            }]
        } else {
            self.sections.clone()
        };

        let section_table_end = 0x58 + OPTIONAL_HEADER_SIZE + (sections.len() * 40);
        let headers_size = align_up(
            u32::try_from(section_table_end)
                .unwrap_or(HEADERS_SIZE)
                .max(HEADERS_SIZE),
            FILE_ALIGNMENT,
        );
        let mut raw_offset = headers_size;
        let mut layout = Vec::new();
        let mut virtual_address = SECTION_ALIGNMENT;
        for section in &sections {
            let raw_size = align_up(
                u32::try_from(section.data.len()).unwrap_or(u32::MAX),
                FILE_ALIGNMENT,
            )
            .max(FILE_ALIGNMENT);
            layout.push((virtual_address, raw_offset, raw_size));
            virtual_address = virtual_address.saturating_add(SECTION_ALIGNMENT);
            raw_offset = raw_offset.saturating_add(raw_size);
        }
        let size_of_image = virtual_address;
        let size_of_headers = headers_size;

        let mut image = vec![0_u8; usize::try_from(raw_offset).unwrap_or(0)];
        write_u16(&mut image, 0, 0x5A4D);
        write_u32(&mut image, 0x3C, 0x40);
        image[0x40..0x44].copy_from_slice(b"PE\0\0");

        let coff = 0x44;
        write_u16(&mut image, coff, 0x8664);
        write_u16(
            &mut image,
            coff + 2,
            u16::try_from(sections.len()).unwrap_or(u16::MAX),
        );
        write_u32(&mut image, coff + 4, self.timestamp);
        write_u16(
            &mut image,
            coff + 16,
            u16::try_from(OPTIONAL_HEADER_SIZE).unwrap_or(u16::MAX),
        );
        write_u16(
            &mut image,
            coff + 18,
            if self.dll { 0x2022 } else { 0x0022 },
        );

        let opt = coff + 20;
        write_u16(&mut image, opt, 0x20B);
        image[opt + 2] = 14;
        write_u32(&mut image, opt + 4, 0x200);
        write_u32(&mut image, opt + 8, 0x200);
        write_u32(&mut image, opt + 12, 0);
        write_u32(
            &mut image,
            opt + 16,
            self.entry_point.unwrap_or(SECTION_ALIGNMENT),
        );
        write_u32(&mut image, opt + 20, SECTION_ALIGNMENT);
        write_u64(&mut image, opt + 24, 0x1_4000_0000);
        write_u32(&mut image, opt + 32, SECTION_ALIGNMENT);
        write_u32(&mut image, opt + 36, FILE_ALIGNMENT);
        write_u16(&mut image, opt + 40, 6);
        write_u16(&mut image, opt + 48, 6);
        write_u32(&mut image, opt + 56, size_of_image);
        write_u32(&mut image, opt + 60, size_of_headers);
        write_u16(&mut image, opt + 68, self.subsystem);
        write_u64(&mut image, opt + 72, 0x0010_0000);
        write_u64(&mut image, opt + 80, 0x1000);
        write_u64(&mut image, opt + 88, 0x0010_0000);
        write_u64(&mut image, opt + 96, 0x1000);
        write_u32(&mut image, opt + 108, 16);

        let section_table = opt + OPTIONAL_HEADER_SIZE;
        for (index, section) in sections.iter().enumerate() {
            let (va, raw, raw_size) = layout[index];
            let base = section_table + (index * 40);
            let name = section.name.as_bytes();
            image[base..base + 8].copy_from_slice(&[0_u8; 8]);
            let name_len = name.len().min(8);
            image[base..base + name_len].copy_from_slice(&name[..name_len]);
            write_u32(&mut image, base + 8, raw_size.max(0x1000));
            write_u32(&mut image, base + 12, va);
            write_u32(&mut image, base + 16, raw_size);
            write_u32(&mut image, base + 20, raw);
            write_u32(&mut image, base + 36, section.characteristics);

            let start = usize::try_from(raw).unwrap_or(0);
            let end = start.saturating_add(section.data.len());
            if let Some(slice) = image.get_mut(start..end) {
                slice.copy_from_slice(&section.data);
            }
        }

        if !self.overlay.is_empty() {
            image.extend_from_slice(&self.overlay);
        }
        image
    }
}

/// Minimal, valid PE32+ image with a single `.text` section.
#[must_use]
pub fn minimal_pe() -> Vec<u8> {
    PeBuilder::new().build()
}

/// The same image with a high-entropy `.text` section and UPX-style names.
#[must_use]
pub fn packed_pe() -> Vec<u8> {
    let data: Vec<u8> = (0..4096_u32)
        .map(|value| {
            let mixed = value.wrapping_mul(2_654_435_761).rotate_left(7);
            u8::try_from((mixed ^ (mixed >> 13)) & 0xFF).unwrap_or_default()
        })
        .collect();
    PeBuilder::new()
        .section_with_flags("UPX0", data.clone(), CHARACTERISTICS_READ_WRITE)
        .section_with_flags("UPX1", data, CHARACTERISTICS_READ_WRITE_EXECUTE)
        .build()
}

#[must_use]
pub fn strings_pe() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"http://malicious.example.com/dropper.bin\x00");
    data.extend_from_slice(b"185.220.101.42\x00");
    data.extend_from_slice(b"C:\\Users\\analyst\\Desktop\\sample.pdb\x00");
    data.extend_from_slice(b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00");
    data.resize(data.len().max(512), 0x90);
    PeBuilder::new().section(".data", data).build()
}

/// Generate deterministic pseudo-random bytes (xorshift), useful for entropy tests.
#[must_use]
pub fn high_entropy_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut value = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        out.push((value & 0xFF) as u8);
    }
    out
}

#[must_use]
pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        value
    } else {
        value.div_ceil(alignment).saturating_mul(alignment)
    }
}

fn write_u16(image: &mut [u8], offset: usize, value: u16) {
    if let Some(slice) = image.get_mut(offset..offset + 2) {
        slice.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u32(image: &mut [u8], offset: usize, value: u32) {
    if let Some(slice) = image.get_mut(offset..offset + 4) {
        slice.copy_from_slice(&value.to_le_bytes());
    }
}

fn write_u64(image: &mut [u8], offset: usize, value: u64) {
    if let Some(slice) = image.get_mut(offset..offset + 8) {
        slice.copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_pe_magic_and_headers() {
        let pe = minimal_pe();
        assert!(pe.starts_with(b"MZ"));
        assert_eq!(&pe[0x40..0x44], b"PE\0\0");
        assert_eq!(u16::from_le_bytes([pe[0x44], pe[0x45]]), 0x8664);
        assert!(pe.len() >= 0x400);
    }

    #[test]
    fn packed_has_named_sections() {
        let pe = packed_pe();
        assert!(pe.windows(4).any(|window| window == b"UPX0"));
        assert!(pe.windows(4).any(|window| window == b"UPX1"));
    }
}

use expe_core::{ElfInfo, ElfSegment, ExpeError, Limits, Result, Section, Structure};
use goblin::elf::Elf;
use goblin::elf::program_header::{
    PF_R, PF_W, PF_X, PT_DYNAMIC, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_NOTE,
};

use crate::entropy;

pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Structure> {
    let elf = Elf::parse(bytes).map_err(|error| ExpeError::Parse {
        format: "ELF".to_string(),
        message: error.to_string(),
    })?;

    let sections = build_sections(bytes, &elf, limits);
    let segments = build_segments(&elf, limits);
    let symbols = build_symbols(&elf, limits);
    let is_stripped =
        sections.iter().all(|section| section.name != ".symtab") || symbols.is_empty();

    Ok(Structure::Elf(ElfInfo {
        class: if elf.is_64 { "64-bit" } else { "32-bit" }.to_string(),
        endianness: if elf.little_endian {
            "little-endian"
        } else {
            "big-endian"
        }
        .to_string(),
        kind: elf_type(elf.header.e_type),
        machine: elf_machine(elf.header.e_machine),
        is_lib: elf.is_lib,
        entry_point: elf.entry,
        interpreter: elf.interpreter.map(str::to_string),
        libraries: elf.libraries.iter().map(|lib| (*lib).to_string()).collect(),
        rpaths: elf.rpaths.iter().map(|path| (*path).to_string()).collect(),
        runpaths: elf
            .runpaths
            .iter()
            .map(|path| (*path).to_string())
            .collect(),
        sections,
        segments,
        symbols,
        build_id: extract_build_id(&elf, bytes),
        is_static: elf.interpreter.is_none(),
        is_stripped,
    }))
}

fn build_sections(bytes: &[u8], elf: &Elf<'_>, limits: &Limits) -> Vec<Section> {
    elf.section_headers
        .iter()
        .take(limits.max_sections)
        .map(|section| {
            let name = elf
                .shdr_strtab
                .get_at(section.sh_name)
                .unwrap_or("")
                .to_string();
            let write = section.sh_flags & u64::from(goblin::elf::section_header::SHF_WRITE) != 0;
            let exec =
                section.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0;
            Section {
                name,
                virtual_address: section.sh_addr,
                virtual_size: section.sh_size,
                raw_offset: section.sh_offset,
                raw_size: section.sh_size,
                entropy: entropy::entropy_of_range(bytes, section.sh_offset, section.sh_size),
                permissions: format!(
                    "{}{}{}",
                    if section.sh_flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0 {
                        'R'
                    } else {
                        '-'
                    },
                    if write { 'W' } else { '-' },
                    if exec { 'X' } else { '-' }
                ),
            }
        })
        .collect()
}

fn build_segments(elf: &Elf<'_>, limits: &Limits) -> Vec<ElfSegment> {
    elf.program_headers
        .iter()
        .take(limits.max_sections)
        .map(|segment| ElfSegment {
            kind: segment_type(segment.p_type),
            permissions: format!(
                "{}{}{}",
                if segment.p_flags & PF_R != 0 {
                    'R'
                } else {
                    '-'
                },
                if segment.p_flags & PF_W != 0 {
                    'W'
                } else {
                    '-'
                },
                if segment.p_flags & PF_X != 0 {
                    'X'
                } else {
                    '-'
                }
            ),
            virtual_address: segment.p_vaddr,
            file_offset: segment.p_offset,
            file_size: segment.p_filesz,
            memory_size: segment.p_memsz,
        })
        .collect()
}

fn build_symbols(elf: &Elf<'_>, limits: &Limits) -> Vec<String> {
    elf.syms
        .iter()
        .filter_map(|symbol| elf.strtab.get_at(symbol.st_name))
        .filter(|name| !name.is_empty())
        .take(limits.max_symbols)
        .map(str::to_string)
        .collect()
}

fn extract_build_id(elf: &Elf<'_>, bytes: &[u8]) -> Option<String> {
    for section in &elf.section_headers {
        if elf.shdr_strtab.get_at(section.sh_name) != Some(".note.gnu.build-id") {
            continue;
        }
        let start = usize::try_from(section.sh_offset).ok()?;
        let size = usize::try_from(section.sh_size).ok()?;
        let data = bytes.get(start..start.checked_add(size)?)?;
        if let Some(desc) = parse_note_descriptor(data) {
            let mut out = String::with_capacity(desc.len() * 2);
            for byte in desc {
                use std::fmt::Write;
                let _ = write!(out, "{byte:02x}");
            }
            return Some(out);
        }
    }
    None
}

fn parse_note_descriptor(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 12 {
        return None;
    }
    let namesz = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?) as usize;
    let descsz = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?) as usize;
    let desc_start = align4(12_usize.checked_add(namesz)?);
    let desc_end = desc_start.checked_add(descsz)?;
    data.get(desc_start..desc_end)
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn elf_type(value: u16) -> String {
    match value {
        1 => "relocatable".to_string(),
        2 => "executable".to_string(),
        3 => "shared object".to_string(),
        4 => "core".to_string(),
        other => format!("unknown ({other})"),
    }
}

fn elf_machine(value: u16) -> String {
    match value {
        3 => "x86".to_string(),
        62 => "x86_64".to_string(),
        40 => "arm".to_string(),
        183 => "arm64".to_string(),
        8 => "mips".to_string(),
        243 => "riscv".to_string(),
        20 | 21 => "powerpc".to_string(),
        other => format!("unknown ({other})"),
    }
}

fn segment_type(value: u32) -> String {
    match value {
        PT_LOAD => "LOAD".to_string(),
        PT_DYNAMIC => "DYNAMIC".to_string(),
        PT_INTERP => "INTERP".to_string(),
        PT_NOTE => "NOTE".to_string(),
        PT_GNU_STACK => "GNU_STACK".to_string(),
        other => format!("0x{other:x}"),
    }
}

use std::collections::{BTreeMap, HashMap};

use expe_core::{
    ExpeError, ExportSymbol, ImportLibrary, ImportedFunction, Limits, Overlay, PeInfo, Result,
    Section, Structure,
};
use goblin::pe::PE;
use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use md5::Md5;
use sha2::Digest;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::entropy;
use crate::io::hashing::hex_bytes;

pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Structure> {
    let pe = PE::parse(bytes).map_err(|error| ExpeError::Parse {
        format: "PE".to_string(),
        message: error.to_string(),
    })?;

    let mut truncated_notes = Vec::new();
    let timestamp = pe.header.coff_header.time_date_stamp;
    let sections = build_sections(bytes, &pe, limits, &mut truncated_notes);
    let imports = build_imports(&pe, limits);
    let exports = build_exports(&pe, limits);
    let debug_pdb = extract_pdb(&pe);
    let overlay = build_overlay(bytes, &pe, &sections);
    let imphash = compute_imphash(&pe);
    let resource_count = pe
        .resource_data
        .as_ref()
        .map_or(0, goblin::pe::resource::ResourceData::count);
    let version_info = extract_version_info(&pe);

    let subsystem = pe.header.optional_header.map_or_else(
        || "unknown".to_string(),
        |opt| subsystem_name(opt.windows_fields.subsystem),
    );

    Ok(Structure::Pe(PeInfo {
        machine: machine_name(pe.header.coff_header.machine),
        subsystem,
        is_64: pe.is_64,
        is_dll: pe.is_lib,
        timestamp,
        timestamp_iso: timestamp_iso(timestamp),
        image_base: pe.image_base,
        entry_point: pe.image_base.saturating_add(u64::from(pe.entry)),
        imphash,
        sections,
        imports,
        exports,
        debug_pdb,
        overlay,
        is_dotnet: pe
            .header
            .optional_header
            .is_some_and(|opt| opt.data_directories.get_clr_runtime_header().is_some()),
        is_signed: pe
            .header
            .optional_header
            .and_then(|opt| opt.data_directories.get_certificate_table().copied())
            .is_some_and(|dir| dir.size > 0),
        has_rich_header: pe.header.rich_header.is_some(),
        tls_callbacks: pe.tls_data.as_ref().map_or(0, |tls| tls.callbacks.len()),
        resource_count,
        version_info,
    }))
}

fn build_sections(
    bytes: &[u8],
    pe: &PE<'_>,
    limits: &Limits,
    notes: &mut Vec<String>,
) -> Vec<Section> {
    let mut sections = Vec::new();
    for section in pe.sections.iter().take(limits.max_sections) {
        let name = section.real_name.clone().unwrap_or_else(|| {
            String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string()
        });
        let raw_offset = u64::from(section.pointer_to_raw_data);
        let raw_size = u64::from(section.size_of_raw_data);
        let permission = format!(
            "{}{}{}",
            if section.characteristics & IMAGE_SCN_MEM_READ != 0 {
                'R'
            } else {
                '-'
            },
            if section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                'W'
            } else {
                '-'
            },
            if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                'X'
            } else {
                '-'
            }
        );
        sections.push(Section {
            name,
            virtual_address: u64::from(section.virtual_address),
            virtual_size: u64::from(section.virtual_size),
            raw_offset,
            raw_size,
            entropy: entropy::entropy_of_range(bytes, raw_offset, raw_size),
            permissions: permission,
        });
    }
    if pe.sections.len() > limits.max_sections {
        notes.push(format!(
            "only the first {} of {} sections were parsed",
            limits.max_sections,
            pe.sections.len()
        ));
    }
    sections
}

fn build_imports(pe: &PE<'_>, limits: &Limits) -> Vec<ImportLibrary> {
    let mut libraries: Vec<ImportLibrary> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();

    for import in pe.imports.iter().take(limits.max_imports) {
        let dll = import.dll.to_string();
        let position = *index.entry(dll.clone()).or_insert_with(|| {
            libraries.push(ImportLibrary {
                dll,
                functions: Vec::new(),
            });
            libraries.len() - 1
        });
        let (name, ordinal) = if import.name.is_empty() {
            (format!("ord#{}", import.ordinal), Some(import.ordinal))
        } else {
            (import.name.to_string(), None)
        };
        libraries[position].functions.push(ImportedFunction {
            name,
            ordinal,
            offset: u64::try_from(import.offset).unwrap_or(u64::MAX),
        });
    }
    libraries
}

fn build_exports(pe: &PE<'_>, limits: &Limits) -> Vec<ExportSymbol> {
    pe.exports
        .iter()
        .take(limits.max_imports)
        .map(|export| {
            let name = export.name.map_or_else(
                || {
                    export
                        .offset
                        .map_or_else(|| format!("rva_{:#x}", export.rva), |o| format!("{o:#x}"))
                },
                str::to_string,
            );
            ExportSymbol {
                name,
                rva: u64::try_from(export.rva).unwrap_or(u64::MAX),
                offset: export
                    .offset
                    .map(|offset| u64::try_from(offset).unwrap_or(u64::MAX)),
            }
        })
        .collect()
}

fn extract_pdb(pe: &PE<'_>) -> Option<String> {
    let debug = pe.debug_data.as_ref()?;
    let raw = debug
        .codeview_pdb70_debug_info
        .as_ref()
        .map(|info| info.filename)
        .or_else(|| {
            debug
                .codeview_pdb20_debug_info
                .as_ref()
                .map(|info| info.filename)
        })?;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let value = String::from_utf8_lossy(&raw[..end]).trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn build_overlay(bytes: &[u8], pe: &PE<'_>, sections: &[Section]) -> Option<Overlay> {
    let header_end = pe
        .header
        .optional_header
        .map_or(0, |opt| opt.windows_fields.size_of_headers as usize);
    let mut end = header_end;
    for section in sections {
        let section_end = usize::try_from(section.raw_offset)
            .unwrap_or(usize::MAX)
            .saturating_add(usize::try_from(section.raw_size).unwrap_or(usize::MAX));
        end = end.max(section_end);
    }
    if end >= bytes.len() {
        return None;
    }
    let overlay = &bytes[end..];
    Some(Overlay {
        offset: end as u64,
        size: overlay.len() as u64,
        entropy: entropy::entropy(overlay),
        embedded: embedded_signatures(overlay),
    })
}

/// Scan a bounded prefix of a blob for common container signatures. Detection only;
/// EXPE never carves or writes anything out.
#[must_use]
pub fn embedded_signatures(data: &[u8]) -> Vec<String> {
    const PREFIX: usize = 4 * 1024 * 1024;
    let data = &data[..data.len().min(PREFIX)];
    let mut found = Vec::new();

    if let Some(position) = memchr::memmem::find(data, b"MZ") {
        let window_end = data.len().min(position + 0x400);
        if memchr::memmem::find(&data[position..window_end], b"PE\0\0").is_some() {
            found.push("PE".to_string());
        }
    }
    if memchr::memmem::find(data, b"\x7fELF").is_some() {
        found.push("ELF".to_string());
    }
    if memchr::memmem::find(data, b"PK\x03\x04").is_some() {
        found.push("ZIP".to_string());
    }
    found
}

fn compute_imphash(pe: &PE<'_>) -> Option<String> {
    if pe.imports.is_empty() {
        return None;
    }
    let mut normalized = Vec::with_capacity(pe.imports.len());
    for import in &pe.imports {
        let dll = import
            .dll
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(import.dll)
            .to_ascii_lowercase();
        let stem = dll.rsplit_once('.').map_or(dll.as_str(), |(stem, _)| stem);
        let function = if import.name.is_empty() {
            format!("ord{}", import.ordinal)
        } else {
            import.name.to_ascii_lowercase()
        };
        normalized.push(format!("{stem}.{function}"));
    }
    Some(hex_bytes(&Md5::digest(normalized.join(",").as_bytes())))
}

fn extract_version_info(pe: &PE<'_>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Some(resource) = pe.resource_data.as_ref() else {
        return map;
    };
    let Some(info) = resource.version_info else {
        return map;
    };
    let strings = &info.string_info;
    let fields = [
        ("company_name", strings.company_name()),
        ("file_description", strings.file_description()),
        ("file_version", strings.file_version()),
        ("internal_name", strings.internal_name()),
        ("original_filename", strings.original_filename()),
        ("product_name", strings.product_name()),
        ("product_version", strings.product_version()),
        ("legal_copyright", strings.legal_copyright()),
    ];
    for (key, value) in fields {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            map.insert(key.to_string(), value);
        }
    }
    map
}

fn timestamp_iso(timestamp: u32) -> Option<String> {
    if timestamp == 0 {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(i64::from(timestamp))
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
}

fn machine_name(machine: u16) -> String {
    match machine {
        0x014c => "x86".to_string(),
        0x8664 => "x86_64".to_string(),
        0x01c0 | 0x01c2 | 0x01c4 => "arm".to_string(),
        0xaa64 => "arm64".to_string(),
        0x0200 => "ia64".to_string(),
        0x5032 => "riscv32".to_string(),
        0x5064 => "riscv64".to_string(),
        0x01f0 => "powerpc".to_string(),
        other => format!("unknown (0x{other:04x})"),
    }
}

fn subsystem_name(subsystem: u16) -> String {
    match subsystem {
        1 => "native".to_string(),
        2 => "windows-gui".to_string(),
        3 => "console".to_string(),
        5 => "os/2 console".to_string(),
        7 => "posix console".to_string(),
        9 => "windows-ce".to_string(),
        10 => "efi-application".to_string(),
        11 => "efi-boot-service".to_string(),
        12 => "efi-runtime".to_string(),
        13 => "efi-rom".to_string(),
        14 => "xbox".to_string(),
        16 => "windows-boot".to_string(),
        other => format!("unknown ({other})"),
    }
}

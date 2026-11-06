use expe_core::{ExpeError, Limits, MachOInfo, MachSegment, Result, Structure};
use goblin::mach::MachO;

pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Structure> {
    let macho = MachO::parse(bytes, 0).map_err(|error| ExpeError::Parse {
        format: "Mach-O".to_string(),
        message: error.to_string(),
    })?;

    let segments = macho
        .segments
        .iter()
        .take(limits.max_sections)
        .map(|segment| {
            let name = segment.name().unwrap_or("").to_string();
            MachSegment {
                name,
                permissions: format!(
                    "{}{}{}",
                    if segment.initprot & 0x1 != 0 {
                        'R'
                    } else {
                        '-'
                    },
                    if segment.initprot & 0x2 != 0 {
                        'W'
                    } else {
                        '-'
                    },
                    if segment.initprot & 0x4 != 0 {
                        'X'
                    } else {
                        '-'
                    }
                ),
                virtual_address: segment.vmaddr,
                file_offset: segment.fileoff,
                file_size: segment.filesize,
            }
        })
        .collect();

    Ok(Structure::MachO(MachOInfo {
        cpu: cpu_name(macho.header.cputype),
        file_type: file_type(macho.header.filetype),
        is_64: macho.is_64,
        entry_point: macho.entry,
        segments,
        libraries: macho.libs.iter().map(|lib| (*lib).to_string()).collect(),
    }))
}

fn cpu_name(value: u32) -> String {
    match value {
        7 => "x86".to_string(),
        0x0100_0007 => "x86_64".to_string(),
        12 => "arm".to_string(),
        0x0100_000c => "arm64".to_string(),
        18 => "powerpc".to_string(),
        other => format!("unknown (0x{other:x})"),
    }
}

fn file_type(value: u32) -> String {
    match value {
        1 => "object".to_string(),
        2 => "executable".to_string(),
        4 => "core".to_string(),
        6 => "dylib".to_string(),
        8 => "bundle".to_string(),
        other => format!("unknown ({other})"),
    }
}

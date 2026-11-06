use std::collections::HashSet;

use expe_core::{Artifact, Category, ElfInfo, Finding, PeInfo, Section, Severity, Structure};
use time::OffsetDateTime;

const HIGH_ENTROPY: f64 = 7.2;

#[must_use]
pub fn analyze(structure: &Structure, _artifact: &Artifact) -> Vec<Finding> {
    let mut findings = Vec::new();

    match structure {
        Structure::Pe(pe) => pe_findings(pe, &mut findings),
        Structure::Elf(elf) => elf_findings(elf, &mut findings),
        Structure::MachO(macho) => {
            for segment in &macho.segments {
                if is_wx(&segment.permissions) {
                    findings.push(Finding::new(
                        "MACHO_WX_SEGMENT",
                        "Writable and executable segment",
                        Severity::High,
                        Category::Injection,
                        format!("segment {} is {}", segment.name, segment.permissions),
                    ));
                }
            }
        }
        Structure::Unavailable => {}
    }

    findings
}

fn pe_findings(pe: &PeInfo, findings: &mut Vec<Finding>) {
    high_entropy_sections(&pe.sections, findings);
    rwx_sections(&pe.sections, findings);

    let packers = packer_sections(&pe.sections);
    if !packers.is_empty() {
        findings.push(
            Finding::new(
                "PE_PACKER_SECTION",
                "Known packer / protector section names",
                Severity::Medium,
                Category::Packing,
                format!("sections: {}", packers.join(", ")),
            )
            .with_attack(&["T1027.002"]),
        );
    }

    if let Some(anomaly) = entry_point_anomaly(pe) {
        findings.push(anomaly);
    }

    let import_count: usize = pe
        .imports
        .iter()
        .map(|library| library.functions.len())
        .sum();
    if import_count < 5 && !pe.is_dotnet && artifact_entropy_hint(pe) {
        findings.push(
            Finding::new(
                "PE_LOW_IMPORT_COUNT",
                "Very small import table",
                Severity::Medium,
                Category::Packing,
                format!(
                    "{import_count} imports with high-entropy code (typical of packed or dynamically resolved payloads)"
                ),
            )
            .with_attack(&["T1027"]),
        );
    }

    if !pe.is_signed {
        findings.push(
            Finding::new(
                "PE_UNSIGNED",
                "Image is not Authenticode-signed",
                Severity::Low,
                Category::FormatAnomaly,
                "no certificate table present",
            )
            .with_attack(&["T1553.002"]),
        );
    }

    if let Some(timestamp) = timestamp_anomaly(pe.timestamp) {
        findings.push(timestamp);
    }

    if let Some(pdb) = &pe.debug_pdb {
        findings.push(
            Finding::new(
                "PE_DEBUG_PATH_LEAK",
                "Debug/build path embedded in the image",
                Severity::Info,
                Category::InformationLeak,
                pdb.clone(),
            )
            .with_attack(&["T1592"]),
        );
    }

    if pe.tls_callbacks > 0 {
        findings.push(
            Finding::new(
                "PE_TLS_CALLBACKS",
                "TLS callbacks present",
                Severity::Low,
                Category::AntiAnalysis,
                format!(
                    "{} TLS callback(s); code runs before the entry point",
                    pe.tls_callbacks
                ),
            )
            .with_attack(&["T1055"]),
        );
    }

    if let Some(overlay) = &pe.overlay {
        if !overlay.embedded.is_empty() {
            findings.push(
                Finding::new(
                    "PE_OVERLAY_EMBEDDED_PE",
                    "Embedded executable in the overlay",
                    Severity::High,
                    Category::Packing,
                    format!(
                        "{} bytes of overlay containing {}",
                        overlay.size,
                        overlay.embedded.join(", ")
                    ),
                )
                .with_attack(&["T1027.009"]),
            );
        } else if overlay.size > 1024 && overlay.entropy > HIGH_ENTROPY {
            findings.push(
                Finding::new(
                    "PE_OVERLAY_HIGH_ENTROPY",
                    "High-entropy overlay",
                    Severity::Low,
                    Category::Packing,
                    format!(
                        "{} byte overlay, entropy {:.2}",
                        overlay.size, overlay.entropy
                    ),
                )
                .with_attack(&["T1027"]),
            );
        }
    }

    if pe.is_dotnet {
        findings.push(Finding::new(
            "PE_DOTNET_ASSEMBLY",
            ".NET assembly",
            Severity::Info,
            Category::FormatAnomaly,
            "CLR runtime header present; managed code may require IL analysis",
        ));
    }

    if !pe.has_rich_header {
        findings.push(Finding::new(
            "PE_NO_RICH_HEADER",
            "No Rich header",
            Severity::Info,
            Category::FormatAnomaly,
            "missing Microsoft linker metadata (common for non-MS toolchains and rebuilt binaries)",
        ));
    }

    for section in &pe.sections {
        if section.name.is_empty() {
            findings.push(Finding::new(
                "PE_EMPTY_SECTION_NAME",
                "Section with an empty name",
                Severity::Medium,
                Category::FormatAnomaly,
                format!("section at RVA {:#x}", section.virtual_address),
            ));
        }
    }

    import_findings(pe, findings);
}

fn elf_findings(elf: &ElfInfo, findings: &mut Vec<Finding>) {
    high_entropy_sections(&elf.sections, findings);

    for segment in &elf.segments {
        if is_wx(&segment.permissions) {
            findings.push(
                Finding::new(
                    "ELF_WX_SEGMENT",
                    "Writable and executable segment",
                    Severity::High,
                    Category::Injection,
                    format!(
                        "{} segment at {:#x} has permissions {}",
                        segment.kind, segment.virtual_address, segment.permissions
                    ),
                )
                .with_attack(&["T1055"]),
            );
        }
    }

    if elf.is_static {
        findings.push(Finding::new(
            "ELF_STATIC_BINARY",
            "Statically linked binary",
            Severity::Low,
            Category::FormatAnomaly,
            "no dynamic interpreter; static payloads are common in embedded malware and droppers",
        ));
    }

    if elf.is_stripped {
        findings.push(Finding::new(
            "ELF_STRIPPED",
            "Symbol table stripped",
            Severity::Info,
            Category::FormatAnomaly,
            "no .symtab or no named symbols",
        ));
    }

    let suspicious_rpath = elf
        .rpaths
        .iter()
        .chain(&elf.runpaths)
        .any(|path| path.contains("$ORIGIN") || path.starts_with('.'));
    if suspicious_rpath {
        findings.push(
            Finding::new(
                "ELF_SUSPICIOUS_RPATH",
                "Relative or $ORIGIN library search path",
                Severity::Medium,
                Category::Packing,
                format!(
                    "rpaths: [{}], runpaths: [{}]",
                    elf.rpaths.join(", "),
                    elf.runpaths.join(", ")
                ),
            )
            .with_attack(&["T1574.006"]),
        );
    }

    let upx = elf
        .sections
        .iter()
        .filter(|section| section.name.to_ascii_lowercase().contains("upx"))
        .count();
    if upx > 0 {
        findings.push(
            Finding::new(
                "ELF_UPX_SECTIONS",
                "UPX section names present",
                Severity::Medium,
                Category::Packing,
                format!("{upx} UPX section(s)"),
            )
            .with_attack(&["T1027.002"]),
        );
    }

    symbol_findings(elf, findings);
}

fn high_entropy_sections(sections: &[Section], findings: &mut Vec<Finding>) {
    let high: Vec<&Section> = sections
        .iter()
        .filter(|section| section.raw_size >= 256 && section.entropy >= HIGH_ENTROPY)
        .collect();
    if high.is_empty() {
        return;
    }
    let evidence = high
        .iter()
        .take(4)
        .map(|section| format!("{} ({:.2})", section.name, section.entropy))
        .collect::<Vec<_>>()
        .join(", ");
    findings.push(
        Finding::new(
            "HIGH_ENTROPY_SECTION",
            "High-entropy section",
            Severity::Medium,
            Category::Packing,
            format!("{evidence} — packed, encrypted or compressed content"),
        )
        .with_attack(&["T1027"]),
    );
}

fn rwx_sections(sections: &[Section], findings: &mut Vec<Finding>) {
    let rwx: Vec<&Section> = sections
        .iter()
        .filter(|section| is_wx(&section.permissions))
        .collect();
    if rwx.is_empty() {
        return;
    }
    findings.push(
        Finding::new(
            "PE_RWX_SECTION",
            "Writable and executable section",
            Severity::High,
            Category::Injection,
            format!(
                "{} ({})",
                rwx.iter()
                    .map(|section| section.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                rwx[0].permissions
            ),
        )
        .with_attack(&["T1055"]),
    );
}

fn packer_sections(sections: &[Section]) -> Vec<String> {
    const PACKERS: &[&str] = &[
        "upx0",
        "upx1",
        "upx2",
        ".aspack",
        ".adata",
        ".themida",
        ".vmp0",
        ".vmp1",
        ".vmp2",
        ".petite",
        "mpress1",
        "mpress2",
        ".nsp0",
        ".nsp1",
        ".neolite",
        ".enigma1",
        ".enigma2",
        ".pklstb",
        ".perplex",
        ".winlice",
        ".sforce",
        ".shrink",
        ".spack",
        ".packed",
        ".pack",
        ".boom",
        ".ccg",
        ".charmve",
        ".ecode",
        ".edata",
        ".maskpe",
        ".mew",
        ".pecompact",
        ".rmnet",
        ".svkp",
        ".taz",
        ".tsuarch",
        ".y0da",
        ".zprotect",
        ".upx",
    ];
    sections
        .iter()
        .filter(|section| {
            let name = section.name.to_ascii_lowercase();
            PACKERS.contains(&name.as_str())
        })
        .map(|section| section.name.clone())
        .collect()
}

fn entry_point_anomaly(pe: &PeInfo) -> Option<Finding> {
    if pe.entry_point < pe.image_base {
        return Some(Finding::new(
            "PE_ENTRYPOINT_ANOMALY",
            "Entry point outside the image",
            Severity::High,
            Category::FormatAnomaly,
            format!(
                "entry {:#x} below image base {:#x}",
                pe.entry_point, pe.image_base
            ),
        ));
    }
    let rva = pe.entry_point - pe.image_base;
    let containing = pe.sections.iter().enumerate().find(|(_, section)| {
        let start = section.virtual_address;
        let span = section.virtual_size.max(section.raw_size);
        rva >= start && rva < start.saturating_add(span)
    });

    match containing {
        None => Some(
            Finding::new(
                "PE_ENTRYPOINT_ANOMALY",
                "Entry point outside any section",
                Severity::High,
                Category::FormatAnomaly,
                format!("RVA {rva:#x} is not mapped by a section"),
            )
            .with_attack(&["T1027"]),
        ),
        Some((_index, section)) if !section.permissions.contains('X') => Some(
            Finding::new(
                "PE_ENTRYPOINT_ANOMALY",
                "Entry point in a non-executable section",
                Severity::High,
                Category::FormatAnomaly,
                format!("RVA {rva:#x} in {} ({})", section.name, section.permissions),
            )
            .with_attack(&["T1027"]),
        ),
        Some((index, section)) if index + 1 == pe.sections.len() && index > 0 => Some(
            Finding::new(
                "PE_ENTRYPOINT_IN_LAST_SECTION",
                "Entry point in the last section",
                Severity::Medium,
                Category::FormatAnomaly,
                format!("RVA {rva:#x} in {}", section.name),
            )
            .with_attack(&["T1027"]),
        ),
        Some(_) => None,
    }
}

fn timestamp_anomaly(timestamp: u32) -> Option<Finding> {
    if timestamp == 0 {
        return Some(Finding::new(
            "PE_TIMESTAMP_ZERO",
            "Zero PE timestamp",
            Severity::Low,
            Category::FormatAnomaly,
            "linker timestamp is zeroed",
        ));
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if i64::from(timestamp) > now + 86_400 {
        return Some(Finding::new(
            "PE_TIMESTAMP_FUTURE",
            "PE timestamp in the future",
            Severity::Low,
            Category::FormatAnomaly,
            format!("timestamp {timestamp} is ahead of the current time"),
        ));
    }
    None
}

fn import_findings(pe: &PeInfo, findings: &mut Vec<Finding>) {
    let imports: HashSet<String> = pe
        .imports
        .iter()
        .flat_map(|library| library.functions.iter())
        .map(|function| {
            function
                .name
                .rsplit('.')
                .next()
                .unwrap_or(&function.name)
                .to_ascii_lowercase()
        })
        .collect();

    struct Group {
        id: &'static str,
        title: &'static str,
        category: Category,
        severity: Severity,
        attack: &'static [&'static str],
        required: usize,
        functions: &'static [&'static str],
    }

    const GROUPS: &[Group] = &[
        Group {
            id: "IMPORT_INJECTION",
            title: "Process injection primitives",
            category: Category::Injection,
            severity: Severity::High,
            attack: &["T1055"],
            required: 2,
            functions: &[
                "virtualallocex",
                "writeprocessmemory",
                "createremotethread",
                "ntcreatethreadex",
                "queueuserapc",
                "setthreadcontext",
                "ntunmapviewofsection",
                "mapviewoffile",
            ],
        },
        Group {
            id: "IMPORT_ANTIDEBUG",
            title: "Anti-debugging / sandbox checks",
            category: Category::AntiAnalysis,
            severity: Severity::Medium,
            attack: &["T1622"],
            required: 2,
            functions: &[
                "isdebuggerpresent",
                "checkremotedebuggerpresent",
                "ntqueryinformationprocess",
                "outputdebugstringa",
                "outputdebugstringw",
                "gettickcount",
                "queryperformancecounter",
            ],
        },
        Group {
            id: "IMPORT_KEYLOG",
            title: "Keystroke capture primitives",
            category: Category::CredentialAccess,
            severity: Severity::High,
            attack: &["T1056.001"],
            required: 2,
            functions: &["getasynckeystate", "setwindowshookexa", "setwindowshookexw"],
        },
        Group {
            id: "IMPORT_PERSISTENCE",
            title: "Persistence primitives",
            category: Category::Persistence,
            severity: Severity::High,
            attack: &["T1547", "T1053"],
            required: 2,
            functions: &[
                "regsetvalueexa",
                "regsetvalueexw",
                "createservicea",
                "createservicew",
                "schtasks",
                "startservicea",
                "startservicew",
            ],
        },
        Group {
            id: "IMPORT_NETWORK",
            title: "Network communication primitives",
            category: Category::Network,
            severity: Severity::Medium,
            attack: &["T1071", "T1105"],
            required: 2,
            functions: &[
                "internetopen",
                "internetopenurla",
                "internetopenurlw",
                "httpsendrequesta",
                "httpsendrequestw",
                "winhttpopen",
                "winhttpconnect",
                "urldownloadtofilea",
                "urldownloadtofilew",
                "wsastartup",
                "connect",
            ],
        },
        Group {
            id: "IMPORT_EXEC",
            title: "Process execution primitives",
            category: Category::Execution,
            severity: Severity::Medium,
            attack: &["T1106"],
            required: 2,
            functions: &[
                "winexec",
                "shellexecutea",
                "shellexecutew",
                "createprocessa",
                "createprocessw",
                "system",
            ],
        },
        Group {
            id: "IMPORT_CRYPTO",
            title: "Cryptographic primitives often used by ransomware",
            category: Category::Crypto,
            severity: Severity::Medium,
            attack: &["T1486"],
            required: 2,
            functions: &[
                "cryptencrypt",
                "cryptdecrypt",
                "cryptgenkey",
                "bcryptencrypt",
                "bcryptdecrypt",
                "bcryptgeneratesymmetrickey",
            ],
        },
        Group {
            id: "IMPORT_PRIVILEGE",
            title: "Privilege manipulation",
            category: Category::PrivilegeEscalation,
            severity: Severity::Medium,
            attack: &["T1134"],
            required: 2,
            functions: &[
                "adjusttokenprivileges",
                "openprocesstoken",
                "lookupprivilegevaluea",
                "lookupprivilegevaluew",
            ],
        },
        Group {
            id: "IMPORT_CREDENTIAL",
            title: "Credential access primitives",
            category: Category::CredentialAccess,
            severity: Severity::High,
            attack: &["T1555"],
            required: 2,
            functions: &[
                "credreada",
                "credreadw",
                "cryptunprotectdata",
                "minidumpwritedump",
                "lsaenumeratelogonSessions",
            ],
        },
        Group {
            id: "IMPORT_DYNAMIC_RESOLUTION",
            title: "Dynamic API resolution",
            category: Category::AntiAnalysis,
            severity: Severity::Low,
            attack: &["T1027"],
            required: 2,
            functions: &["loadlibrarya", "loadlibraryw", "getprocaddress"],
        },
    ];

    for group in GROUPS {
        let matched: Vec<&str> = group
            .functions
            .iter()
            .copied()
            .filter(|function| imports.contains(*function))
            .collect();
        if matched.len() >= group.required {
            findings.push(
                Finding::new(
                    group.id,
                    group.title,
                    group.severity,
                    group.category,
                    format!("imports: {}", matched.join(", ")),
                )
                .with_attack(group.attack),
            );
        }
    }
}

fn symbol_findings(elf: &ElfInfo, findings: &mut Vec<Finding>) {
    let symbols: HashSet<&str> = elf.symbols.iter().map(String::as_str).collect();

    let injection = [
        "process_vm_writev",
        "process_vm_readv",
        "memfd_create",
        "ptrace",
        "mprotect",
    ];
    let injection_hits: Vec<&str> = injection
        .iter()
        .copied()
        .filter(|symbol| symbols.contains(symbol))
        .collect();
    if injection_hits.len() >= 2 {
        findings.push(
            Finding::new(
                "ELF_INJECTION_SYMBOLS",
                "Memory manipulation symbols",
                Severity::High,
                Category::Injection,
                format!("symbols: {}", injection_hits.join(", ")),
            )
            .with_attack(&["T1055"]),
        );
    }

    let privilege = [
        "setuid",
        "setgid",
        "seteuid",
        "setegid",
        "setreuid",
        "setresuid",
    ];
    let privilege_hits: Vec<&str> = privilege
        .iter()
        .copied()
        .filter(|symbol| symbols.contains(symbol))
        .collect();
    if privilege_hits.len() >= 2 {
        findings.push(
            Finding::new(
                "ELF_PRIVILEGE_SYMBOLS",
                "Privilege-changing symbols",
                Severity::Medium,
                Category::PrivilegeEscalation,
                format!("symbols: {}", privilege_hits.join(", ")),
            )
            .with_attack(&["T1548"]),
        );
    }
}

fn is_wx(permissions: &str) -> bool {
    permissions.contains('W') && permissions.contains('X')
}

/// PE heuristics do not have access to the whole-file entropy here, so use the
/// presence of any high-entropy section as the signal.
fn artifact_entropy_hint(pe: &PeInfo) -> bool {
    pe.sections
        .iter()
        .any(|section| section.raw_size >= 1024 && section.entropy >= HIGH_ENTROPY)
}

#[cfg(test)]
mod tests {
    use expe_core::{Arch, FileKind, Format, Hashes, ImportLibrary, ImportedFunction};

    use super::*;

    fn artifact() -> Artifact {
        Artifact {
            path: None,
            file_name: "x.exe".to_string(),
            size: 10,
            format: Format::Pe,
            arch: Arch::X86_64,
            kind: FileKind::Executable,
            entropy: 7.5,
            hashes: Hashes::default(),
        }
    }

    fn section(name: &str, perms: &str, entropy: f64) -> Section {
        Section {
            name: name.to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_offset: 0x200,
            raw_size: 0x1000,
            entropy,
            permissions: perms.to_string(),
        }
    }

    #[test]
    fn detects_rwx_and_entropy() {
        let pe = PeInfo {
            sections: vec![section(".text", "RWX", 7.8)],
            ..PeInfo::default()
        };
        let findings = analyze(&Structure::Pe(pe), &artifact());
        assert!(findings.iter().any(|f| f.id == "PE_RWX_SECTION"));
        assert!(findings.iter().any(|f| f.id == "HIGH_ENTROPY_SECTION"));
    }

    #[test]
    fn detects_packer_names() {
        let pe = PeInfo {
            sections: vec![section("UPX0", "R-X", 3.0)],
            ..PeInfo::default()
        };
        let findings = analyze(&Structure::Pe(pe), &artifact());
        assert!(findings.iter().any(|f| f.id == "PE_PACKER_SECTION"));
    }

    #[test]
    fn detects_injection_imports() {
        let pe = PeInfo {
            imports: vec![ImportLibrary {
                dll: "kernel32.dll".to_string(),
                functions: vec![
                    ImportedFunction {
                        name: "VirtualAllocEx".to_string(),
                        ordinal: None,
                        offset: 0,
                    },
                    ImportedFunction {
                        name: "WriteProcessMemory".to_string(),
                        ordinal: None,
                        offset: 0,
                    },
                ],
            }],
            is_signed: true,
            has_rich_header: true,
            ..PeInfo::default()
        };
        let findings = analyze(&Structure::Pe(pe), &artifact());
        assert!(findings.iter().any(|f| f.id == "IMPORT_INJECTION"));
    }

    #[test]
    fn entry_point_anomaly_is_detected() {
        let pe = PeInfo {
            image_base: 0x400000,
            entry_point: 0x500000,
            sections: vec![section(".text", "R-X", 6.0)],
            is_signed: true,
            has_rich_header: true,
            ..PeInfo::default()
        };
        let findings = analyze(&Structure::Pe(pe), &artifact());
        assert!(findings.iter().any(|f| f.id == "PE_ENTRYPOINT_ANOMALY"));
    }

    #[test]
    fn elf_wx_segment_is_detected() {
        let elf = ElfInfo {
            segments: vec![expe_core::ElfSegment {
                kind: "LOAD".to_string(),
                permissions: "RWX".to_string(),
                virtual_address: 0x400000,
                file_offset: 0,
                file_size: 10,
                memory_size: 10,
            }],
            ..ElfInfo::default()
        };
        let findings = analyze(&Structure::Elf(elf), &artifact());
        assert!(findings.iter().any(|f| f.id == "ELF_WX_SEGMENT"));
    }
}

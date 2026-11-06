use std::fmt::Write as _;

use expe_core::{AnalysisReport, IocGroup, Severity, Structure};

use super::sanitize::{sanitize, truncate};

pub fn render(report: &AnalysisReport, defang: bool) -> String {
    let mut out = String::new();
    let width = 78;
    let _ = writeln!(out, "{}", "═".repeat(width));
    let _ = writeln!(
        out,
        "EXPE  {}  ·  static binary triage",
        report.tool.version
    );
    let _ = writeln!(out, "{}", "═".repeat(width));
    render_artifact(&mut out, report);
    render_risk(&mut out, report);
    render_findings(&mut out, report);
    render_iocs(&mut out, report, defang);
    render_structure(&mut out, &report.structure);
    let _ = writeln!(
        out,
        "\nStrings: {} (ascii {}, utf16 {}){}",
        report.strings.total,
        report.strings.ascii,
        report.strings.utf16le,
        if report.strings.truncated {
            "  [truncated]"
        } else {
            ""
        }
    );
    if !report.limits.notes.is_empty() {
        let _ = writeln!(out, "Limits:");
        for note in &report.limits.notes {
            let _ = writeln!(out, "  · {}", sanitize(note));
        }
    }
    let _ = writeln!(out, "Analysis time: {} ms", report.timing_ms);
    out
}

pub fn render_artifact(out: &mut String, report: &AnalysisReport) {
    let artifact = &report.artifact;
    let _ = writeln!(out, "File      {}", sanitize(&artifact.file_name));
    if let Some(path) = &artifact.path {
        let _ = writeln!(out, "Path      {}", sanitize(path));
    }
    let _ = writeln!(
        out,
        "Format    {} {} · {} · {} B",
        artifact.format.label(),
        artifact.arch.label(),
        artifact.kind.label(),
        artifact.size
    );
    let _ = writeln!(out, "Entropy   {:.2} bits/byte", artifact.entropy);
    let _ = writeln!(out, "MD5       {}", artifact.hashes.md5);
    let _ = writeln!(out, "SHA1      {}", artifact.hashes.sha1);
    let _ = writeln!(out, "SHA256    {}", artifact.hashes.sha256);
    if let Some(imphash) = &artifact.hashes.imphash {
        let _ = writeln!(out, "Imphash   {imphash}");
    }
}

pub fn render_risk(out: &mut String, report: &AnalysisReport) {
    let width = 78;
    let _ = writeln!(out, "\n{}", "─".repeat(width));
    let filled = usize::from(report.risk.score) * 30 / 100;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(30 - filled));
    let _ = writeln!(
        out,
        "RISK  {:>3}/100  {:<10}  {}",
        report.risk.score,
        report.risk.verdict.label().to_uppercase(),
        bar
    );
    for factor in &report.risk.factors {
        let _ = writeln!(
            out,
            "      {:<24} {:>3} pts{}",
            factor.category.label(),
            factor.capped_points,
            if factor.points > factor.capped_points {
                "  (capped)"
            } else {
                ""
            }
        );
    }
}

pub fn render_findings(out: &mut String, report: &AnalysisReport) {
    let width = 78;
    let _ = writeln!(out, "\n{}", "─".repeat(width));
    let _ = writeln!(out, "FINDINGS ({})", report.findings.len());
    if report.findings.is_empty() {
        let _ = writeln!(out, "  none");
        return;
    }
    for finding in report.sorted_findings() {
        let severity = finding.severity.label().to_uppercase();
        let _ = writeln!(
            out,
            "  {:<8} {:<24} {}",
            severity,
            truncate(&finding.id, 24),
            sanitize(&finding.title)
        );
        let _ = writeln!(
            out,
            "           {}",
            truncate(&sanitize(&finding.evidence), 90)
        );
        if !finding.attack.is_empty() {
            let _ = writeln!(out, "           ATT&CK: {}", finding.attack.join(", "));
        }
    }
}

pub fn render_iocs(out: &mut String, report: &AnalysisReport, defang: bool) {
    let width = 78;
    let total = report.ioc_count();
    let _ = writeln!(out, "\n{}", "─".repeat(width));
    let _ = writeln!(out, "IOCs ({total})");
    if total == 0 {
        let _ = writeln!(out, "  none");
        return;
    }
    for group in &report.iocs {
        render_ioc_group(out, group, defang);
    }
}

pub fn render_ioc_group(out: &mut String, group: &IocGroup, defang: bool) {
    let _ = writeln!(out, "  {}", group.kind.label());
    for item in &group.items {
        let value = if defang { &item.defanged } else { &item.value };
        let scope = item
            .scope
            .map(|scope| format!(" [{}]", scope.label()))
            .unwrap_or_default();
        let confidence = format!(" [{}]", item.confidence.label());
        let _ = writeln!(
            out,
            "    {:<58}{}{}",
            truncate(&sanitize(value), 58),
            scope,
            confidence
        );
        if !item.offsets.is_empty() && item.offsets.len() <= 4 {
            let offsets = item
                .offsets
                .iter()
                .map(|offset| format!("{offset:#x}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                out,
                "      offsets: {offsets} · {}",
                item.sources
                    .iter()
                    .map(|s| s.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

pub fn render_structure(out: &mut String, structure: &Structure) {
    let width = 78;
    let _ = writeln!(out, "\n{}", "─".repeat(width));
    let _ = writeln!(out, "STRUCTURE");
    match structure {
        Structure::Pe(pe) => {
            let _ = writeln!(
                out,
                "  PE {} · {} · entry {:#x} · image base {:#x}",
                pe.machine, pe.subsystem, pe.entry_point, pe.image_base
            );
            if let Some(timestamp) = &pe.timestamp_iso {
                let _ = writeln!(out, "  compiled {timestamp}");
            }
            let _ = writeln!(
                out,
                "  DLL {} · .NET {} · signed {} · rich header {} · resource dirs {} · TLS callbacks {}",
                pe.is_dll,
                pe.is_dotnet,
                pe.is_signed,
                pe.has_rich_header,
                pe.resource_count,
                pe.tls_callbacks
            );
            if let Some(pdb) = &pe.debug_pdb {
                let _ = writeln!(out, "  PDB {}", sanitize(pdb));
            }
            if let Some(overlay) = &pe.overlay {
                let _ = writeln!(
                    out,
                    "  Overlay {} B at {:#x} · entropy {:.2}{}",
                    overlay.size,
                    overlay.offset,
                    overlay.entropy,
                    if overlay.embedded.is_empty() {
                        String::new()
                    } else {
                        format!(" · embedded {}", overlay.embedded.join(", "))
                    }
                );
            }
            let _ = writeln!(out, "  Sections");
            for section in &pe.sections {
                let _ = writeln!(
                    out,
                    "    {:<10} VA {:#010x}  raw {:#010x}  {:>7} B  {:.2}  {}",
                    truncate(&section.name, 10),
                    section.virtual_address,
                    section.raw_offset,
                    section.raw_size,
                    section.entropy,
                    section.permissions
                );
            }
            let import_count: usize = pe
                .imports
                .iter()
                .map(|library| library.functions.len())
                .sum();
            let _ = writeln!(
                out,
                "  Imports {} across {} DLL(s) · exports {}",
                import_count,
                pe.imports.len(),
                pe.exports.len()
            );
            for library in pe.imports.iter().take(6) {
                let functions = library
                    .functions
                    .iter()
                    .take(12)
                    .map(|function| sanitize(&function.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(out, "    {}: {}", sanitize(&library.dll), functions);
            }
            if !pe.version_info.is_empty() {
                let _ = writeln!(out, "  Version info");
                for (key, value) in &pe.version_info {
                    let _ = writeln!(out, "    {key}: {}", sanitize(value));
                }
            }
        }
        Structure::Elf(elf) => {
            let _ = writeln!(
                out,
                "  ELF {} {} {} · entry {:#x}",
                elf.class, elf.endianness, elf.kind, elf.entry_point
            );
            if let Some(interpreter) = &elf.interpreter {
                let _ = writeln!(out, "  Interpreter {}", sanitize(interpreter));
            }
            let _ = writeln!(
                out,
                "  static {} · stripped {} · libraries {} · rpaths {}",
                elf.is_static,
                elf.is_stripped,
                elf.libraries.len(),
                elf.rpaths.len() + elf.runpaths.len()
            );
            if !elf.libraries.is_empty() {
                let _ = writeln!(
                    out,
                    "    {}",
                    elf.libraries
                        .iter()
                        .take(12)
                        .map(|lib| sanitize(lib))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let _ = writeln!(out, "  Sections");
            for section in &elf.sections {
                let _ = writeln!(
                    out,
                    "    {:<16} VA {:#010x}  {:>7} B  {:.2}  {}",
                    truncate(&section.name, 16),
                    section.virtual_address,
                    section.raw_size,
                    section.entropy,
                    section.permissions
                );
            }
        }
        Structure::MachO(macho) => {
            let _ = writeln!(
                out,
                "  Mach-O {} · {} · entry {:#x}",
                macho.cpu, macho.file_type, macho.entry_point
            );
            for segment in &macho.segments {
                let _ = writeln!(
                    out,
                    "    {:<16} {:#010x}  {:>7} B  {}",
                    truncate(&segment.name, 16),
                    segment.virtual_address,
                    segment.file_size,
                    segment.permissions
                );
            }
        }
        Structure::Unavailable => {
            let _ = writeln!(out, "  not parsed");
        }
    }
}

#[allow(dead_code)]
pub fn render_iocs_only(report: &AnalysisReport, defang: bool, kinds: &[String]) -> String {
    let mut out = String::new();
    for group in &report.iocs {
        if !kinds.is_empty()
            && !kinds
                .iter()
                .any(|kind| kind.eq_ignore_ascii_case(group.kind.as_str()))
        {
            continue;
        }
        render_ioc_group(&mut out, group, defang);
    }
    if out.is_empty() {
        out.push_str("no matching IOCs\n");
    }
    out
}

pub fn render_strings(items: &[expe_core::ExtractedString], defang: bool) -> String {
    let mut out = String::new();
    for item in items {
        let value = if defang {
            sanitize(&expe_core::defang(&item.value, expe_core::IocKind::Domain))
        } else {
            sanitize(&item.value)
        };
        let _ = writeln!(
            out,
            "{:>10}  {:<8} {}",
            format!("{:#x}", item.offset),
            item.encoding.label(),
            truncate(&value, 120)
        );
    }
    out
}

#[allow(dead_code)]
pub fn severity_label(severity: Severity) -> &'static str {
    severity.label()
}

use std::fmt::Write as _;

use expe_core::{AnalysisReport, Structure};

use super::sanitize::sanitize;

pub fn render(report: &AnalysisReport, defang: bool) -> String {
    let mut out = String::new();
    let artifact = &report.artifact;
    let _ = writeln!(out, "# EXPE report — `{}`\n", cell(&artifact.file_name));
    let _ = writeln!(
        out,
        "> **Risk {} / 100 — {}** · {} {} · {} B · SHA256 `{}`\n",
        report.risk.score,
        report.risk.verdict.label().to_uppercase(),
        artifact.format.label(),
        artifact.arch.label(),
        artifact.size,
        artifact.hashes.sha256
    );

    let _ = writeln!(out, "## Artifact\n");
    let _ = writeln!(out, "| Field | Value |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| File | {} |", cell(&artifact.file_name));
    if let Some(path) = &artifact.path {
        let _ = writeln!(out, "| Path | {} |", cell(path));
    }
    let _ = writeln!(
        out,
        "| Format | {} ({}, {}) |",
        artifact.format.label(),
        artifact.arch.label(),
        artifact.kind.label()
    );
    let _ = writeln!(out, "| Size | {} bytes |", artifact.size);
    let _ = writeln!(out, "| Entropy | {:.2} bits/byte |", artifact.entropy);
    let _ = writeln!(out, "| MD5 | `{}` |", artifact.hashes.md5);
    let _ = writeln!(out, "| SHA1 | `{}` |", artifact.hashes.sha1);
    let _ = writeln!(out, "| SHA256 | `{}` |", artifact.hashes.sha256);
    if let Some(imphash) = &artifact.hashes.imphash {
        let _ = writeln!(out, "| Imphash | `{imphash}` |");
    }

    let _ = writeln!(out, "\n## Risk breakdown\n");
    let _ = writeln!(out, "| Category | Points | Capped |");
    let _ = writeln!(out, "|---|---:|---:|");
    for factor in &report.risk.factors {
        let _ = writeln!(
            out,
            "| {} | {} | {} |",
            factor.category.label(),
            factor.points,
            factor.capped_points
        );
    }

    let _ = writeln!(out, "\n## Findings ({})\n", report.findings.len());
    if report.findings.is_empty() {
        let _ = writeln!(out, "_No heuristic findings._");
    } else {
        let _ = writeln!(out, "| Severity | ID | Finding | Evidence | ATT&CK |");
        let _ = writeln!(out, "|---|---|---|---|---|");
        for finding in report.sorted_findings() {
            let _ = writeln!(
                out,
                "| {} | `{}` | {} | {} | {} |",
                finding.severity.label().to_uppercase(),
                cell(&finding.id),
                cell(&finding.title),
                cell(&finding.evidence),
                finding.attack.join(", ")
            );
        }
    }

    let _ = writeln!(out, "\n## IOCs ({})\n", report.ioc_count());
    if report.ioc_count() == 0 {
        let _ = writeln!(out, "_No indicators extracted._");
    }
    for group in &report.iocs {
        let _ = writeln!(out, "### {}\n", group.kind.label());
        let _ = writeln!(out, "| Value | Scope | Confidence | Sources |");
        let _ = writeln!(out, "|---|---|---|---|");
        for item in &group.items {
            let value = if defang { &item.defanged } else { &item.value };
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                cell(value),
                item.scope.map_or("—", |scope| scope.label()),
                item.confidence.label(),
                item.sources
                    .iter()
                    .map(|source| source.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        out.push('\n');
    }

    let _ = writeln!(out, "## Structure\n");
    render_structure(&mut out, &report.structure);

    if !report.limits.notes.is_empty() {
        let _ = writeln!(out, "\n## Limits\n");
        for note in &report.limits.notes {
            let _ = writeln!(out, "- {}", cell(note));
        }
    }
    let _ = writeln!(
        out,
        "\n_Analysis time: {} ms; ruleset {}._",
        report.timing_ms, report.tool.ruleset_version
    );
    out
}

fn render_structure(out: &mut String, structure: &Structure) {
    match structure {
        Structure::Pe(pe) => {
            let _ = writeln!(
                out,
                "PE `{}`, subsystem `{}`, entry `{:#x}`, image base `{:#x}`, compiled `{}`.\n",
                pe.machine,
                pe.subsystem,
                pe.entry_point,
                pe.image_base,
                pe.timestamp_iso.as_deref().unwrap_or("unknown")
            );
            let _ = writeln!(out, "| Section | VA | Raw | Entropy | Perms |");
            let _ = writeln!(out, "|---|---:|---:|---:|---|");
            for section in &pe.sections {
                let _ = writeln!(
                    out,
                    "| {} | `{:#x}` | {} B | {:.2} | `{}` |",
                    cell(&section.name),
                    section.virtual_address,
                    section.raw_size,
                    section.entropy,
                    section.permissions
                );
            }
            if let Some(overlay) = &pe.overlay {
                let _ = writeln!(
                    out,
                    "\nOverlay: {} bytes at `{:#x}`, entropy {:.2}{}.",
                    overlay.size,
                    overlay.offset,
                    overlay.entropy,
                    if overlay.embedded.is_empty() {
                        String::new()
                    } else {
                        format!(", embedded {}", overlay.embedded.join(", "))
                    }
                );
            }
        }
        Structure::Elf(elf) => {
            let _ = writeln!(
                out,
                "ELF {} {} {}, entry `{:#x}`, interpreter `{}`, static `{}`, stripped `{}`.\n",
                elf.class,
                elf.endianness,
                elf.kind,
                elf.entry_point,
                elf.interpreter.as_deref().unwrap_or("none"),
                elf.is_static,
                elf.is_stripped
            );
            let _ = writeln!(out, "| Section | VA | Size | Entropy | Perms |");
            let _ = writeln!(out, "|---|---:|---:|---:|---|");
            for section in &elf.sections {
                let _ = writeln!(
                    out,
                    "| {} | `{:#x}` | {} B | {:.2} | `{}` |",
                    cell(&section.name),
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
                "Mach-O `{}`, type `{}`, entry `{:#x}`.",
                macho.cpu, macho.file_type, macho.entry_point
            );
            let _ = writeln!(out, "| Segment | VA | Size | Perms |");
            let _ = writeln!(out, "|---|---:|---:|---|");
            for segment in &macho.segments {
                let _ = writeln!(
                    out,
                    "| {} | `{:#x}` | {} B | `{}` |",
                    cell(&segment.name),
                    segment.virtual_address,
                    segment.file_size,
                    segment.permissions
                );
            }
        }
        Structure::Unavailable => {
            let _ = writeln!(out, "_Structure parsing unavailable._");
        }
    }
}

fn cell(value: &str) -> String {
    sanitize(value).replace('|', "\\|")
}

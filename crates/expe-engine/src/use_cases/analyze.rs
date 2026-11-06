use std::path::Path;
use std::time::Instant;

use expe_core::{
    AnalysisOutcome, AnalysisReport, Arch, Artifact, ArtifactBytes, ArtifactReader, ExpeError,
    FileKind, Format, Limits, LimitsReport, Result, SCHEMA_VERSION, Structure, ToolInfo,
    score_findings,
};

use crate::entropy;
use crate::heuristics;
use crate::io::{FileReader, hash_bytes};
use crate::ioc::IocExtractor;
use crate::parse::{archive_kind, detect, parse_structure};
use crate::rules::RuleSet;
use crate::strings;

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub limits: Limits,
    pub include_strings: bool,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            include_strings: false,
        }
    }
}

pub struct Analyzer {
    reader: FileReader,
    rules: RuleSet,
}

/// Coarse pipeline stages for interactive progress. Headless callers can ignore
/// them; the TUI renders them as a live stepper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Reading,
    Parsing,
    Strings,
    Indicators,
    Heuristics,
    Scoring,
}

impl Stage {
    pub const ALL: [Self; 6] = [
        Self::Reading,
        Self::Parsing,
        Self::Strings,
        Self::Indicators,
        Self::Heuristics,
        Self::Scoring,
    ];

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Reading => "reading + hashing",
            Self::Parsing => "parsing structure",
            Self::Strings => "extracting strings",
            Self::Indicators => "extracting indicators",
            Self::Heuristics => "running heuristics",
            Self::Scoring => "scoring risk",
        }
    }

    /// One-based position, convenient for `3/6` display.
    #[must_use]
    pub fn position(self) -> usize {
        Self::ALL
            .iter()
            .position(|stage| *stage == self)
            .map_or(1, |index| index + 1)
    }

    #[must_use]
    pub fn total() -> usize {
        Self::ALL.len()
    }
}

impl Analyzer {
    pub fn with_default_rules() -> Result<Self> {
        Ok(Self::new(RuleSet::load_default()?))
    }

    #[must_use]
    pub fn new(rules: RuleSet) -> Self {
        Self {
            reader: FileReader,
            rules,
        }
    }

    #[must_use]
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn analyze_path(&self, path: &Path, options: &AnalyzeOptions) -> Result<AnalysisOutcome> {
        self.analyze_path_with_progress(path, options, &mut |_| {})
    }

    /// Same as [`Self::analyze_path`] but reports coarse stages. The callback runs
    /// on the calling thread; it must be cheap and must not panic.
    pub fn analyze_path_with_progress(
        &self,
        path: &Path,
        options: &AnalyzeOptions,
        progress: &mut dyn FnMut(Stage),
    ) -> Result<AnalysisOutcome> {
        let started = Instant::now();
        progress(Stage::Reading);
        let data = self.reader.read(path, &options.limits)?;
        let mut outcome = self.analyze_loaded(&data, Some(path), options, progress)?;
        outcome.report.timing_ms = elapsed_ms(started);
        Ok(outcome)
    }

    /// Analyze already-loaded bytes (tests, stdin, TUI retries).
    pub fn analyze_bytes(
        &self,
        file_name: &str,
        bytes: std::sync::Arc<[u8]>,
        options: &AnalyzeOptions,
    ) -> Result<AnalysisOutcome> {
        let started = Instant::now();
        let data = ArtifactBytes {
            hashes: hash_bytes(&bytes),
            bytes,
        };
        let mut outcome =
            self.analyze_loaded(&data, Some(Path::new(file_name)), options, &mut |_| {})?;
        outcome.report.timing_ms = elapsed_ms(started);
        Ok(outcome)
    }

    fn analyze_loaded(
        &self,
        data: &ArtifactBytes,
        path: Option<&Path>,
        options: &AnalyzeOptions,
        progress: &mut dyn FnMut(Stage),
    ) -> Result<AnalysisOutcome> {
        let bytes = data.bytes.as_ref();
        let format = detect(bytes);
        if format == Format::Archive {
            let kind = archive_kind(bytes).unwrap_or("archive");
            return Err(ExpeError::UnsupportedFormat(format!(
                "{kind} archive; EXPE never extracts or executes samples. Inspect contents in an isolated environment first"
            )));
        }
        if format == Format::Unknown {
            return Err(ExpeError::UnsupportedFormat(
                "unrecognized file signature; expected PE, ELF or Mach-O".to_string(),
            ));
        }

        progress(Stage::Parsing);
        let structure = parse_structure(bytes, format, &options.limits)?;
        progress(Stage::Strings);
        let string_scan = strings::scan(bytes, &options.limits);
        progress(Stage::Indicators);
        let ioc_result =
            IocExtractor::new(&self.rules).extract(&string_scan.items, &structure, &options.limits);
        progress(Stage::Heuristics);
        let artifact = build_artifact(path, data, format, &structure, bytes, &options.limits);
        let findings = heuristics::analyze(&structure, &artifact);
        progress(Stage::Scoring);
        let risk = score_findings(&findings);

        let mut notes = Vec::new();
        if ioc_result.truncated {
            notes.push(format!(
                "IOC list truncated at the {} item cap",
                options.limits.max_iocs
            ));
        }
        if string_scan.truncated {
            notes.push(format!(
                "string list truncated at the {} item cap",
                options.limits.max_strings
            ));
        }

        let sections_truncated = match &structure {
            Structure::Pe(pe) => pe.sections.len() >= options.limits.max_sections,
            Structure::Elf(elf) => elf.sections.len() >= options.limits.max_sections,
            Structure::MachO(macho) => macho.segments.len() >= options.limits.max_sections,
            Structure::Unavailable => false,
        };
        if sections_truncated {
            notes.push(format!(
                "section list truncated at the {} item cap",
                options.limits.max_sections
            ));
        }
        let imports_truncated = match &structure {
            Structure::Pe(pe) => {
                pe.imports
                    .iter()
                    .map(|library| library.functions.len())
                    .sum::<usize>()
                    >= options.limits.max_imports
            }
            _ => false,
        };

        let report = AnalysisReport {
            schema_version: SCHEMA_VERSION.to_string(),
            tool: ToolInfo {
                name: "expe".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                schema_version: SCHEMA_VERSION.to_string(),
                ruleset_version: self.rules.version.clone(),
            },
            artifact,
            structure,
            strings: string_scan.summary(options.include_strings),
            iocs: ioc_result.groups,
            findings,
            risk,
            limits: LimitsReport {
                bytes_scanned: string_scan.scanned_bytes,
                strings_truncated: string_scan.truncated,
                iocs_truncated: ioc_result.truncated,
                sections_truncated,
                imports_truncated,
                notes,
            },
            timing_ms: 0,
        };

        Ok(AnalysisOutcome {
            report,
            raw: Some(data.bytes.clone()),
        })
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn build_artifact(
    path: Option<&Path>,
    data: &ArtifactBytes,
    format: Format,
    structure: &Structure,
    bytes: &[u8],
    limits: &Limits,
) -> Artifact {
    let (arch, kind, imphash) = match structure {
        Structure::Pe(pe) => (
            arch_from_label(&pe.machine),
            if pe.is_dll {
                FileKind::SharedLibrary
            } else {
                FileKind::Executable
            },
            pe.imphash.clone(),
        ),
        Structure::Elf(elf) => (
            arch_from_label(&elf.machine),
            if elf.is_lib {
                FileKind::SharedLibrary
            } else {
                FileKind::Executable
            },
            None,
        ),
        Structure::MachO(macho) => (
            arch_from_label(&macho.cpu),
            if macho.file_type == "dylib" {
                FileKind::SharedLibrary
            } else {
                FileKind::Executable
            },
            None,
        ),
        Structure::Unavailable => (Arch::Unknown, FileKind::Unknown, None),
    };

    let file_name = path.and_then(Path::file_name).map_or_else(
        || "memory".to_string(),
        |name| name.to_string_lossy().to_string(),
    );

    let mut hashes = data.hashes.clone();
    hashes.imphash = imphash;

    Artifact {
        path: path.map(|path| path.to_string_lossy().to_string()),
        file_name,
        size: bytes.len() as u64,
        format,
        arch,
        kind,
        entropy: entropy::entropy_sampled(bytes, limits.max_scan_bytes),
        hashes,
    }
}

fn arch_from_label(label: &str) -> Arch {
    match label {
        "x86" | "i386" | "i686" => Arch::X86,
        "x86_64" | "amd64" => Arch::X86_64,
        "arm" | "armv7" => Arch::Arm,
        "arm64" | "aarch64" => Arch::Arm64,
        "mips" => Arch::Mips,
        "riscv" | "riscv64" => Arch::RiscV,
        "ppc" | "powerpc" => Arch::PowerPc,
        _ => Arch::Unknown,
    }
}

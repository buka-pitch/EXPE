//! Pure domain layer for EXPE.
//!
//! This crate has no filesystem, parser, terminal or network dependencies. It owns
//! the vocabulary shared by every adapter: artifacts, normalized structures, IOCs,
//! findings, scoring and the versioned report.

pub mod artifact;
pub mod error;
pub mod finding;
pub mod ioc;
pub mod limits;
pub mod ports;
pub mod report;
pub mod scoring;
pub mod string;
pub mod structure;

pub use artifact::{Arch, Artifact, ArtifactBytes, FileKind, Format, Hashes};
pub use error::{ExpeError, Result};
pub use finding::{Category, Finding, Severity};
pub use ioc::{Confidence, Ioc, IocGroup, IocKind, IocSource, IpScope, defang};
pub use limits::Limits;
pub use ports::{ArtifactReader, BinaryParser, Reporter};
pub use report::{
    AnalysisOutcome, AnalysisReport, LimitsReport, OutputFormat, SCHEMA_VERSION, ToolInfo,
};
pub use scoring::{Risk, RiskFactor, Verdict, score_findings};
pub use string::{ExtractedString, StringEncoding, StringsSummary};
pub use structure::{
    ElfInfo, ElfSegment, ExportSymbol, ImportLibrary, ImportedFunction, MachOInfo, MachSegment,
    Overlay, PeInfo, Section, Structure,
};

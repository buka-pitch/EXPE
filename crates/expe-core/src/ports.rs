use std::path::Path;

use crate::artifact::{ArtifactBytes, Format};
use crate::error::Result;
use crate::limits::Limits;
use crate::report::{AnalysisReport, OutputFormat};
use crate::structure::Structure;

/// Reads an artifact into memory under a hard size cap and computes hashes.
pub trait ArtifactReader {
    fn read(&self, path: &Path, limits: &Limits) -> Result<ArtifactBytes>;
}

/// Turns bytes into a normalized structure. Implementations must be treated as
/// hostile-input boundaries (panic isolation happens in the engine).
pub trait BinaryParser {
    fn supports(&self, bytes: &[u8]) -> Option<Format>;
    fn parse(&self, bytes: &[u8], limits: &Limits) -> Result<Structure>;
}

/// Presentation seam shared by the CLI and the TUI export action.
pub trait Reporter {
    fn format(&self) -> OutputFormat;
    fn render(&self, report: &AnalysisReport) -> Result<Vec<u8>>;
}

use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::artifact::Artifact;
use crate::finding::Finding;
use crate::ioc::IocGroup;
use crate::scoring::Risk;
use crate::string::StringsSummary;
use crate::structure::Structure;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub schema_version: String,
    pub ruleset_version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct LimitsReport {
    pub bytes_scanned: u64,
    pub strings_truncated: bool,
    pub iocs_truncated: bool,
    pub sections_truncated: bool,
    pub imports_truncated: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisReport {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub artifact: Artifact,
    pub structure: Structure,
    pub strings: StringsSummary,
    pub iocs: Vec<IocGroup>,
    pub findings: Vec<Finding>,
    pub risk: Risk,
    pub limits: LimitsReport,
    pub timing_ms: u64,
}

impl AnalysisReport {
    /// Findings sorted by severity (highest first), then id, for deterministic output.
    #[must_use]
    pub fn sorted_findings(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self.findings.iter().collect();
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.id.cmp(&b.id))
                .then_with(|| a.evidence.cmp(&b.evidence))
        });
        findings
    }

    /// All IOCs flattened, grouped in kind order.
    #[must_use]
    pub fn ioc_count(&self) -> usize {
        self.iocs.iter().map(|g| g.items.len()).sum()
    }
}

/// Full in-memory result. `raw` is deliberately not serialized and is retained
/// only for interactive views (hex viewer) and dropped by headless callers.
#[derive(Debug, Clone)]
pub struct AnalysisOutcome {
    pub report: AnalysisReport,
    pub raw: Option<Arc<[u8]>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Text,
    Markdown,
}

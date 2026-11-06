use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Hard resource bounds. Every bound is surfaced in [`crate::report::LimitsReport`]
/// when it is hit, so a report never silently hides truncation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Largest file accepted by the reader (bytes).
    pub max_file_size: u64,
    /// Largest prefix scanned for strings / embedded artifacts (bytes).
    pub max_scan_bytes: u64,
    /// Shortest accepted string, in characters.
    pub min_string_len: usize,
    /// Longer runs are truncated to this length and flagged.
    pub max_string_len: usize,
    /// Maximum number of unique strings retained.
    pub max_strings: usize,
    /// Maximum number of IOC values retained.
    pub max_iocs: usize,
    /// Maximum sections/segments retained.
    pub max_sections: usize,
    /// Maximum imports retained across all libraries.
    pub max_imports: usize,
    /// Maximum symbols retained.
    pub max_symbols: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: 512 * 1024 * 1024,
            max_scan_bytes: 256 * 1024 * 1024,
            min_string_len: 4,
            max_string_len: 512,
            max_strings: 100_000,
            max_iocs: 10_000,
            max_sections: 256,
            max_imports: 50_000,
            max_symbols: 5_000,
        }
    }
}

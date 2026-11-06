use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

impl StringEncoding {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf16Le => "utf-16le",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractedString {
    pub value: String,
    /// File offset of the first byte of the string.
    pub offset: u64,
    pub encoding: StringEncoding,
    pub occurrences: u32,
    /// True when the run was longer than the configured maximum and was cut.
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct StringsSummary {
    pub total: usize,
    pub ascii: usize,
    pub utf16le: usize,
    pub truncated: bool,
    /// Full list only when the caller asks for it; otherwise empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<ExtractedString>,
}

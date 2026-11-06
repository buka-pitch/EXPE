use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    #[must_use]
    pub fn weight(self) -> u32 {
        match self {
            Self::Info => 0,
            Self::Low => 2,
            Self::Medium => 6,
            Self::High => 12,
            Self::Critical => 20,
        }
    }

    #[must_use]
    pub fn satisfies(self, threshold: Self) -> bool {
        self >= threshold
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Packing,
    Injection,
    Network,
    AntiAnalysis,
    Persistence,
    Crypto,
    CredentialAccess,
    PrivilegeEscalation,
    Execution,
    Discovery,
    FormatAnomaly,
    InformationLeak,
}

impl Category {
    /// Every category, used by scoring tests and report grouping.
    pub const ALL: [Self; 12] = [
        Self::Packing,
        Self::Injection,
        Self::Network,
        Self::AntiAnalysis,
        Self::Persistence,
        Self::Crypto,
        Self::CredentialAccess,
        Self::PrivilegeEscalation,
        Self::Execution,
        Self::Discovery,
        Self::FormatAnomaly,
        Self::InformationLeak,
    ];

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Packing => "Packing / obfuscation",
            Self::Injection => "Process injection",
            Self::Network => "Network",
            Self::AntiAnalysis => "Anti-analysis",
            Self::Persistence => "Persistence",
            Self::Crypto => "Cryptography",
            Self::CredentialAccess => "Credential access",
            Self::PrivilegeEscalation => "Privilege escalation",
            Self::Execution => "Execution",
            Self::Discovery => "Discovery",
            Self::FormatAnomaly => "Format anomaly",
            Self::InformationLeak => "Information leak",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: Category,
    pub evidence: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<String>,
}

impl Finding {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        category: Category,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            severity,
            category,
            evidence: evidence.into(),
            attack: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_attack(mut self, techniques: &[&str]) -> Self {
        self.attack = techniques.iter().map(|t| (*t).to_string()).collect();
        self
    }
}

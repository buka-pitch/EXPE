use std::path::PathBuf;

/// Every failure in EXPE is classified so the CLI can pick a stable exit code.
#[derive(Debug, thiserror::Error)]
pub enum ExpeError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("unsupported or unrecognized format: {0}")]
    UnsupportedFormat(String),

    #[error("{format} parser rejected the input: {message}")]
    Parse { format: String, message: String },

    #[error("input exceeds safety limit: {0}")]
    LimitExceeded(String),

    #[error("invalid rule set: {0}")]
    Rule(String),

    #[error("cannot render report: {0}")]
    Output(String),

    #[error("{0}")]
    Config(String),
}

impl ExpeError {
    /// Stable process exit code for headless callers.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) | Self::Rule(_) => 4,
            Self::Io { .. }
            | Self::Parse { .. }
            | Self::UnsupportedFormat(_)
            | Self::LimitExceeded(_)
            | Self::Output(_) => 2,
        }
    }
}

pub type Result<T> = std::result::Result<T, ExpeError>;

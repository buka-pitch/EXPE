use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Pe,
    Elf,
    #[serde(rename = "macho")]
    MachO,
    Archive,
    #[default]
    Unknown,
}

impl Format {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pe => "PE",
            Self::Elf => "ELF",
            Self::MachO => "Mach-O",
            Self::Archive => "Archive",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    RiscV,
    PowerPc,
    #[default]
    Unknown,
}

impl Arch {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Mips => "mips",
            Self::RiscV => "riscv",
            Self::PowerPc => "ppc",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Executable,
    SharedLibrary,
    Driver,
    Object,
    Script,
    Data,
    #[default]
    Unknown,
}

impl FileKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::SharedLibrary => "shared library",
            Self::Driver => "driver",
            Self::Object => "object",
            Self::Script => "script",
            Self::Data => "data",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Artifact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub file_name: String,
    pub size: u64,
    pub format: Format,
    pub arch: Arch,
    pub kind: FileKind,
    pub entropy: f64,
    pub hashes: Hashes,
}

/// Byte payload plus hashes produced by a reader.
#[derive(Debug, Clone)]
pub struct ArtifactBytes {
    pub bytes: std::sync::Arc<[u8]>,
    pub hashes: Hashes,
}

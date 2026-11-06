use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Email,
    RegistryKey,
    WindowsPath,
    UnixPath,
    Mutex,
    NamedPipe,
    PdbPath,
    BitcoinAddress,
    EthereumAddress,
    OnionAddress,
    EmbeddedPe,
    EmbeddedElf,
}

impl IocKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Domain => "Domain",
            Self::Url => "URL",
            Self::Email => "Email",
            Self::RegistryKey => "Registry key",
            Self::WindowsPath => "Windows path",
            Self::UnixPath => "Unix path",
            Self::Mutex => "Mutex",
            Self::NamedPipe => "Named pipe",
            Self::PdbPath => "PDB path",
            Self::BitcoinAddress => "Bitcoin",
            Self::EthereumAddress => "Ethereum",
            Self::OnionAddress => "Onion",
            Self::EmbeddedPe => "Embedded PE",
            Self::EmbeddedElf => "Embedded ELF",
        }
    }

    /// Stable `snake_case` identifier used by rule files and CLI filters.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Email => "email",
            Self::RegistryKey => "registry_key",
            Self::WindowsPath => "windows_path",
            Self::UnixPath => "unix_path",
            Self::Mutex => "mutex",
            Self::NamedPipe => "named_pipe",
            Self::PdbPath => "pdb_path",
            Self::BitcoinAddress => "bitcoin_address",
            Self::EthereumAddress => "ethereum_address",
            Self::OnionAddress => "onion_address",
            Self::EmbeddedPe => "embedded_pe",
            Self::EmbeddedElf => "embedded_elf",
        }
    }

    /// Parse the `snake_case` identifier used by rule files and CLI filters.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "domain" => Self::Domain,
            "url" => Self::Url,
            "email" => Self::Email,
            "registry_key" => Self::RegistryKey,
            "windows_path" => Self::WindowsPath,
            "unix_path" => Self::UnixPath,
            "mutex" => Self::Mutex,
            "named_pipe" => Self::NamedPipe,
            "pdb_path" => Self::PdbPath,
            "bitcoin_address" => Self::BitcoinAddress,
            "ethereum_address" => Self::EthereumAddress,
            "onion_address" => Self::OnionAddress,
            "embedded_pe" => Self::EmbeddedPe,
            "embedded_elf" => Self::EmbeddedElf,
            _ => return None,
        })
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum IocSource {
    Strings,
    Imports,
    Exports,
    SectionNames,
    Debug,
    VersionInfo,
    Overlay,
}

impl IocSource {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Strings => "strings",
            Self::Imports => "imports",
            Self::Exports => "exports",
            Self::SectionNames => "sections",
            Self::Debug => "debug",
            Self::VersionInfo => "version-info",
            Self::Overlay => "overlay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpScope {
    Public,
    Private,
    Loopback,
    Reserved,
    LinkLocal,
}

impl IpScope {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Loopback => "loopback",
            Self::Reserved => "reserved",
            Self::LinkLocal => "link-local",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    pub defanged: String,
    pub sources: Vec<IocSource>,
    pub offsets: Vec<u64>,
    pub occurrences: u32,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<IpScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

impl Ioc {
    #[must_use]
    pub fn confidence_rank(&self) -> u8 {
        match self.confidence {
            Confidence::Low => 0,
            Confidence::Medium => 1,
            Confidence::High => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IocGroup {
    pub kind: IocKind,
    pub items: Vec<Ioc>,
}

/// Neutralize clickable / dangerous punctuation. Kept deliberately simple so the
/// output stays copy-paste friendly.
#[must_use]
pub fn defang(value: &str, kind: IocKind) -> String {
    match kind {
        IocKind::Url => value
            .replace("https://", "hxxps://")
            .replace("http://", "hxxp://")
            .replace('.', "[.]"),
        IocKind::Domain
        | IocKind::Ipv4
        | IocKind::Ipv6
        | IocKind::Email
        | IocKind::OnionAddress => value.replace('.', "[.]").replace('@', "[at]"),
        _ => value.replace('.', "[.]"),
    }
}

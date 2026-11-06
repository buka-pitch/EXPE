use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Normalized view over PE / ELF / Mach-O structures. Values are display-ready but
/// keep raw numeric fields so downstream consumers can recompute anything.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "data", rename_all = "lowercase")]
pub enum Structure {
    Pe(PeInfo),
    Elf(ElfInfo),
    #[serde(rename = "macho")]
    MachO(MachOInfo),
    Unavailable,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub entropy: f64,
    /// Permission string in the order `R W X`, e.g. `RWX`, `R-X`, `R--`.
    pub permissions: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ImportedFunction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u16>,
    /// File offset of the import entry, used to trace IOC provenance.
    pub offset: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ImportLibrary {
    pub dll: String,
    pub functions: Vec<ImportedFunction>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ExportSymbol {
    pub name: String,
    pub rva: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Overlay {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    /// Detected signatures inside the overlay, e.g. `PE`, `ELF`, `ZIP`.
    pub embedded: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PeInfo {
    pub machine: String,
    pub subsystem: String,
    pub is_64: bool,
    pub is_dll: bool,
    pub timestamp: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_iso: Option<String>,
    pub image_base: u64,
    pub entry_point: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    pub sections: Vec<Section>,
    pub imports: Vec<ImportLibrary>,
    pub exports: Vec<ExportSymbol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_pdb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<Overlay>,
    pub is_dotnet: bool,
    pub is_signed: bool,
    pub has_rich_header: bool,
    pub tls_callbacks: usize,
    pub resource_count: u16,
    pub version_info: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ElfSegment {
    pub kind: String,
    pub permissions: String,
    pub virtual_address: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ElfInfo {
    pub class: String,
    pub endianness: String,
    pub kind: String,
    pub machine: String,
    pub is_lib: bool,
    pub entry_point: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    pub libraries: Vec<String>,
    pub rpaths: Vec<String>,
    pub runpaths: Vec<String>,
    pub sections: Vec<Section>,
    pub segments: Vec<ElfSegment>,
    pub symbols: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    pub is_static: bool,
    pub is_stripped: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct MachSegment {
    pub name: String,
    pub permissions: String,
    pub virtual_address: u64,
    pub file_offset: u64,
    pub file_size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct MachOInfo {
    pub cpu: String,
    pub file_type: String,
    pub is_64: bool,
    pub entry_point: u64,
    pub segments: Vec<MachSegment>,
    pub libraries: Vec<String>,
}

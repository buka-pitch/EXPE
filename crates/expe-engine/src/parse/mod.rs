pub mod detect;
pub mod elf;
pub mod macho;
pub mod pe;

use std::panic::{AssertUnwindSafe, catch_unwind};

use expe_core::{ExpeError, Format, Limits, Result, Structure};

use self::detect::detect_format;

pub use self::detect::archive_kind;

/// Parse bytes while containing panics from third-party parsers. A panic becomes a
/// normal parse error and the process keeps running.
pub fn parse_structure(bytes: &[u8], format: Format, limits: &Limits) -> Result<Structure> {
    let parsed = catch_unwind(AssertUnwindSafe(|| match format {
        Format::Pe => pe::parse(bytes, limits),
        Format::Elf => elf::parse(bytes, limits),
        Format::MachO => macho::parse(bytes, limits),
        Format::Archive | Format::Unknown => Ok(Structure::Unavailable),
    }));

    match parsed {
        Ok(result) => result,
        Err(_) => Err(ExpeError::Parse {
            format: format.label().to_string(),
            message: "parser panicked on malformed input; contained by EXPE".to_string(),
        }),
    }
}

pub fn detect(bytes: &[u8]) -> Format {
    detect_format(bytes)
}

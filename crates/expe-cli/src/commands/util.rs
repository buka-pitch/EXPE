use std::io::Write;
use std::path::Path;

use expe_core::{AnalysisReport, ExpeError, IocKind, Result, Severity};

/// Write to a file or stdout. Files are created with default permissions; EXPE
/// never writes next to the sample automatically.
pub fn write_bytes(bytes: &[u8], output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        std::fs::write(path, bytes).map_err(|source| ExpeError::Io {
            path: path.to_path_buf(),
            source,
        })
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(bytes)
            .and_then(|()| stdout.flush())
            .map_err(|error| ExpeError::Output(error.to_string()))
    }
}

pub fn write_text(text: &str, output: Option<&Path>) -> Result<()> {
    write_bytes(text.as_bytes(), output)
}

/// True when any finding reaches the threshold. Info findings never trigger.
pub fn threshold_reached(report: &AnalysisReport, threshold: Option<Severity>) -> bool {
    threshold.is_some_and(|threshold| {
        report
            .findings
            .iter()
            .any(|finding| finding.severity.satisfies(threshold))
    })
}

pub fn parse_kind_filter(types: Option<&str>) -> Result<Vec<IocKind>> {
    let Some(types) = types else {
        return Ok(Vec::new());
    };
    let mut kinds = Vec::new();
    for value in types.split(',') {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let kind = IocKind::parse(value).ok_or_else(|| {
            ExpeError::Config(format!(
                "unknown IOC type '{value}'; expected one of ipv4, ipv6, domain, url, email, \
                 registry_key, windows_path, unix_path, mutex, named_pipe, pdb_path, \
                 bitcoin_address, ethereum_address, onion_address, embedded_pe, embedded_elf"
            ))
        })?;
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    Ok(kinds)
}

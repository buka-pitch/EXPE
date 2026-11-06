use std::fmt::Write as _;

use expe_core::{ExpeError, Result};
use expe_engine::rules::RuleSet;

use crate::cli::{RulesArgs, RulesCommand};
use crate::commands::util;
use crate::output::sanitize::sanitize;

pub fn run(args: &RulesArgs) -> Result<i32> {
    match &args.command {
        RulesCommand::List { file } => list(file.clone()),
        RulesCommand::Check { file } => check(file),
    }
}

// The header literals are kept as arguments so the column widths stay aligned.
#[allow(clippy::write_literal)]
fn list(file: Option<std::path::PathBuf>) -> Result<i32> {
    let mut set = RuleSet::load_default()?;
    if let Some(path) = file {
        let user = RuleSet::load_path(&path)?;
        set = set.merge(&user)?;
    }

    let mut out = String::new();
    let _ = writeln!(out, "ruleset {} · {} rules\n", set.version, set.rules.len());
    let _ = writeln!(
        out,
        "{:<28} {:<18} {:<8} {:<7} {}",
        "ID", "KIND", "SEVERITY", "CONF", "VALIDATOR"
    );
    let _ = writeln!(out, "{}", "─".repeat(90));
    for rule in &set.rules {
        let _ = writeln!(
            out,
            "{:<28} {:<18} {:<8} {:<7} {}",
            sanitize(&rule.def.id),
            rule.kind.as_str(),
            rule.def.severity.label(),
            rule.confidence().label(),
            rule.def.validator
        );
    }
    util::write_text(&out, None)?;
    Ok(0)
}

fn check(file: &std::path::Path) -> Result<i32> {
    let text = std::fs::read_to_string(file).map_err(|source| ExpeError::Io {
        path: file.to_path_buf(),
        source,
    })?;
    let (version, count) = RuleSet::check(&text)?;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "valid rule pack: {} (ruleset {version}, {count} rule(s))",
        sanitize(&file.display().to_string())
    );
    util::write_text(&out, None)?;
    Ok(0)
}

use std::path::PathBuf;

use expe_core::{AnalysisOutcome, ExpeError, Result, Severity};
use expe_engine::use_cases::batch::discover_files;
use expe_engine::{AnalyzeOptions, Analyzer};
use rayon::prelude::*;
use serde_json::json;

use crate::cli::{BatchArgs, BatchFormat};
use crate::commands::util;
use crate::output::sanitize::sanitize;

type Entry = (PathBuf, Result<AnalysisOutcome>);

pub fn run(args: BatchArgs) -> Result<i32> {
    if args.paths.is_empty() {
        return Err(ExpeError::Config(
            "batch needs at least one file or directory".to_string(),
        ));
    }
    let files = discover_files(&args.paths, args.recursive)?;
    if files.is_empty() {
        return Err(ExpeError::Config(
            "no regular files found for the supplied paths".to_string(),
        ));
    }

    let analyzer = args.rules.build_analyzer()?;
    let options = AnalyzeOptions::default();
    let threshold = args.fail_on.map(crate::cli::FailOnArg::severity);

    let entries = if args.fail_fast {
        analyze_sequential(&analyzer, &files, &options, threshold)
    } else {
        analyze_parallel(&analyzer, &files, &options, args.jobs)?
    };

    let rendered = match args.format {
        BatchFormat::Text => render_text(&entries, threshold).into_bytes(),
        BatchFormat::Json => render_json(&entries)?,
        BatchFormat::Jsonl => render_jsonl(&entries)?,
    };
    util::write_bytes(&rendered, args.output.as_deref())?;

    let reached = entries.iter().any(|(_, result)| {
        result
            .as_ref()
            .is_ok_and(|outcome| util::threshold_reached(&outcome.report, threshold))
    });
    if reached {
        return Ok(1);
    }
    if entries.iter().any(|(_, result)| result.is_err()) {
        return Ok(2);
    }
    Ok(0)
}

fn analyze_sequential(
    analyzer: &Analyzer,
    files: &[PathBuf],
    options: &AnalyzeOptions,
    threshold: Option<Severity>,
) -> Vec<Entry> {
    let mut entries = Vec::new();
    for file in files {
        let result = analyzer.analyze_path(file, options);
        let stop = result.is_err()
            || result
                .as_ref()
                .is_ok_and(|outcome| util::threshold_reached(&outcome.report, threshold));
        entries.push((file.clone(), result));
        if stop {
            break;
        }
    }
    entries
}

fn analyze_parallel(
    analyzer: &Analyzer,
    files: &[PathBuf],
    options: &AnalyzeOptions,
    jobs: usize,
) -> Result<Vec<Entry>> {
    let work = || {
        files
            .par_iter()
            .map(|file| (file.clone(), analyzer.analyze_path(file, options)))
            .collect::<Vec<Entry>>()
    };
    if jobs == 0 {
        Ok(work())
    } else {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build()
            .map_err(|error| ExpeError::Config(format!("cannot create worker pool: {error}")))?;
        Ok(pool.install(work))
    }
}

fn render_text(entries: &[Entry], threshold: Option<Severity>) -> String {
    let mut out = String::new();
    let mut ok = 0_usize;
    let mut errors = 0_usize;
    for (path, result) in entries {
        match result {
            Ok(outcome) => {
                ok += 1;
                let report = &outcome.report;
                out.push_str(&format!(
                    "ok    {:<52} {:<6} {:<8} risk {:>3} {:<10} findings {:>2}  iocs {:>3}\n",
                    sanitize(&path.display().to_string()),
                    report.artifact.format.label(),
                    report.artifact.arch.label(),
                    report.risk.score,
                    report.risk.verdict.label(),
                    report.findings.len(),
                    report.ioc_count()
                ));
            }
            Err(error) => {
                errors += 1;
                out.push_str(&format!(
                    "error {:<52} {}\n",
                    sanitize(&path.display().to_string()),
                    sanitize(&error.to_string())
                ));
            }
        }
    }
    out.push_str(&format!(
        "\n{} file(s): {} ok, {} error(s), threshold {}\n",
        entries.len(),
        ok,
        errors,
        threshold.map_or_else(|| "none".to_string(), |value| value.label().to_string())
    ));
    out
}

fn render_json(entries: &[Entry]) -> Result<Vec<u8>> {
    let values: Vec<serde_json::Value> = entries
        .iter()
        .map(|(path, result)| entry_value(path, result))
        .collect();
    let mut bytes =
        serde_json::to_vec_pretty(&values).map_err(|error| ExpeError::Output(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn render_jsonl(entries: &[Entry]) -> Result<Vec<u8>> {
    let mut out = String::new();
    for (path, result) in entries {
        let value = entry_value(path, result);
        let line =
            serde_json::to_string(&value).map_err(|error| ExpeError::Output(error.to_string()))?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out.into_bytes())
}

fn entry_value(path: &PathBuf, result: &Result<AnalysisOutcome>) -> serde_json::Value {
    match result {
        Ok(outcome) => json!({
            "path": path.to_string_lossy(),
            "ok": true,
            "report": outcome.report,
        }),
        Err(error) => json!({
            "path": path.to_string_lossy(),
            "ok": false,
            "error": error.to_string(),
        }),
    }
}

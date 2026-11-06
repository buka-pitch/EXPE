use crate::cli::{FormatArg, InfoArgs};
use crate::commands::util;
use crate::output::{json, markdown, text};
use expe_core::Result;

pub fn run(args: &InfoArgs) -> Result<i32> {
    let analyzer = args.rules.build_analyzer()?;
    let outcome = analyzer.analyze_path(&args.path, &expe_engine::AnalyzeOptions::default())?;
    let report = &outcome.report;

    let rendered = match args.format {
        FormatArg::Json => json::render(report)?,
        FormatArg::Markdown => markdown::render(report, false).into_bytes(),
        FormatArg::Text => {
            let mut out = String::new();
            text::render_artifact(&mut out, report);
            text::render_structure(&mut out, &report.structure);
            out.into_bytes()
        }
    };

    util::write_bytes(&rendered, args.output.as_deref())?;
    Ok(0)
}

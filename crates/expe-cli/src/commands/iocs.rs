use crate::cli::{FormatArg, IocsArgs};
use crate::commands::util;
use crate::output::{json, markdown, text};
use expe_core::Result;

pub fn run(args: IocsArgs) -> Result<i32> {
    let analyzer = args.rules.build_analyzer()?;
    let mut report = analyzer
        .analyze_path(&args.path, &expe_engine::AnalyzeOptions::default())?
        .report;

    let kinds = util::parse_kind_filter(args.types.as_deref())?;
    if !kinds.is_empty() {
        report.iocs.retain(|group| kinds.contains(&group.kind));
    }

    let rendered = match args.format {
        FormatArg::Json => json::render(&report)?,
        FormatArg::Markdown => markdown::render(&report, args.defang).into_bytes(),
        FormatArg::Text => {
            let mut out = String::new();
            text::render_iocs(&mut out, &report, args.defang);
            out.into_bytes()
        }
    };

    util::write_bytes(&rendered, args.output.as_deref())?;
    Ok(0)
}

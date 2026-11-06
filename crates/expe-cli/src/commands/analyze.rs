use crate::cli::{self, AnalyzeArgs};
use crate::commands::util;
use expe_core::Result;

pub fn run(args: AnalyzeArgs) -> Result<i32> {
    let analyzer = args.rules.build_analyzer()?;
    let options = cli::options_from_args(&args);
    let outcome = analyzer.analyze_path(&args.path, &options)?;
    let rendered = cli::render(&outcome.report, args.format, args.defang)?;
    util::write_bytes(&rendered, args.output.as_deref())?;

    if util::threshold_reached(&outcome.report, args.fail_on.map(cli::FailOnArg::severity)) {
        return Ok(1);
    }
    Ok(0)
}

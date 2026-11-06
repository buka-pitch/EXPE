use crate::cli::TuiArgs;
use expe_core::Result;
use expe_engine::AnalyzeOptions;

pub fn run(args: TuiArgs) -> Result<i32> {
    let analyzer = args.rules.build_analyzer()?;
    let mut options = AnalyzeOptions::default();
    // The interactive views need string rows and retained bytes.
    options.include_strings = true;
    expe_tui::run(args.path, analyzer, options)?;
    Ok(0)
}

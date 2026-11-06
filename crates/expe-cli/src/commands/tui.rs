use crate::cli::TuiArgs;
use expe_core::Result;
use expe_engine::AnalyzeOptions;

pub fn run(args: &TuiArgs) -> Result<i32> {
    let analyzer = args.rules.build_analyzer()?;
    // The interactive views need string rows and retained bytes.
    let options = AnalyzeOptions {
        include_strings: true,
        ..AnalyzeOptions::default()
    };
    expe_tui::run(args.path.clone(), analyzer, &options)?;
    Ok(0)
}

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use expe_core::{AnalysisReport, ExpeError, Result, Severity};
use expe_engine::{AnalyzeOptions, Analyzer, rules::RuleSet};

use crate::commands;
use crate::output::{json, markdown, text};

#[derive(Debug, Parser)]
#[command(
    name = "expe",
    version,
    about = "EXPE (explore PE) — safe binary parser, IOC extractor and triage console",
    long_about = "EXPE (explore PE) parses PE, ELF and Mach-O samples without executing or extracting them. \
                  It extracts strings and indicators, detects packers and suspicious imports, \
                  and produces deterministic JSON or an interactive terminal console.",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyze a binary and print a report.
    Analyze(AnalyzeArgs),
    /// Show normalized structure only.
    Info(InfoArgs),
    /// Extract strings with offsets.
    Strings(StringsArgs),
    /// Extract indicators only.
    Iocs(IocsArgs),
    /// Scan many files (directories supported).
    Batch(BatchArgs),
    /// Open the interactive terminal console.
    #[command(visible_alias = "ui")]
    Tui(TuiArgs),
    /// Inspect or validate IOC rule packs.
    Rules(RulesArgs),
    /// Print the JSON Schema for analysis reports.
    Schema,
}

#[derive(Debug, Clone, Args)]
pub struct RuleArgs {
    /// Additional rule pack (overrides matching ids; may be repeated).
    #[arg(long = "rules", value_name = "FILE")]
    pub rules: Vec<PathBuf>,
    /// Ignore the embedded default rule pack.
    #[arg(long)]
    pub no_default_rules: bool,
}

impl RuleArgs {
    pub fn build_analyzer(&self) -> Result<Analyzer> {
        let mut set = if self.no_default_rules {
            RuleSet::empty()?
        } else {
            RuleSet::load_default()?
        };
        for path in &self.rules {
            let user = RuleSet::load_path(path)?;
            set = set.merge(&user)?;
        }
        Ok(Analyzer::new(set))
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum FormatArg {
    #[default]
    Text,
    Json,
    Markdown,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FailOnArg {
    Low,
    Medium,
    High,
    Critical,
}

impl FailOnArg {
    #[must_use]
    pub fn severity(self) -> Severity {
        match self {
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
            Self::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EncodingArg {
    Ascii,
    Utf16le,
    Both,
}

#[derive(Debug, Args)]
pub struct AnalyzeArgs {
    pub path: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    pub format: FormatArg,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub include_strings: bool,
    #[arg(long)]
    pub defang: bool,
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOnArg>,
    #[arg(long, default_value_t = 4)]
    pub min_string_len: usize,
    #[arg(long)]
    pub max_strings: Option<usize>,
    #[arg(long)]
    pub max_iocs: Option<usize>,
    #[arg(long)]
    pub max_scan_bytes: Option<u64>,
    #[command(flatten)]
    pub rules: RuleArgs,
}

#[derive(Debug, Args)]
pub struct InfoArgs {
    pub path: PathBuf,
    #[arg(long, value_enum, default_value = "text")]
    pub format: FormatArg,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[command(flatten)]
    pub rules: RuleArgs,
}

#[derive(Debug, Args)]
pub struct StringsArgs {
    pub path: PathBuf,
    #[arg(long, value_enum, default_value = "both")]
    pub encoding: EncodingArg,
    #[arg(long, default_value_t = 4)]
    pub min_len: usize,
    #[arg(long)]
    pub regex: Option<String>,
    #[arg(long, default_value_t = 200)]
    pub limit: usize,
    #[arg(long)]
    pub defang: bool,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct IocsArgs {
    pub path: PathBuf,
    /// Comma-separated kinds, e.g. `ipv4,domain,url`.
    #[arg(long)]
    pub types: Option<String>,
    #[arg(long)]
    pub defang: bool,
    #[arg(long, value_enum, default_value = "text")]
    pub format: FormatArg,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[command(flatten)]
    pub rules: RuleArgs,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BatchFormat {
    Text,
    Json,
    Jsonl,
}

#[derive(Debug, Args)]
pub struct BatchArgs {
    pub paths: Vec<PathBuf>,
    #[arg(long)]
    pub recursive: bool,
    /// Worker threads; 0 uses the available parallelism.
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,
    #[arg(long, value_enum, default_value = "text")]
    pub format: BatchFormat,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub fail_fast: bool,
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOnArg>,
    #[arg(long)]
    pub defang: bool,
    #[command(flatten)]
    pub rules: RuleArgs,
}

#[derive(Debug, Args)]
pub struct TuiArgs {
    pub path: Option<PathBuf>,
    #[command(flatten)]
    pub rules: RuleArgs,
}

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// List rules from the default and optional user packs.
    List {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Validate a rule pack and report rule count.
    Check { file: PathBuf },
}

pub fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.command {
        Command::Analyze(args) => commands::analyze::run(&args),
        Command::Info(args) => commands::info::run(&args),
        Command::Strings(args) => commands::strings::run(&args),
        Command::Iocs(args) => commands::iocs::run(&args),
        Command::Batch(args) => commands::batch::run(&args),
        Command::Tui(args) => commands::tui::run(&args),
        Command::Rules(args) => commands::rules::run(&args),
        Command::Schema => {
            let schema = schemars::schema_for!(AnalysisReport);
            let rendered = serde_json::to_string_pretty(&schema)
                .map_err(|error| ExpeError::Output(error.to_string()))?;
            println!("{rendered}");
            Ok(0)
        }
    }
}

pub fn render(report: &AnalysisReport, format: FormatArg, defang: bool) -> Result<Vec<u8>> {
    match format {
        FormatArg::Json => json::render(report),
        FormatArg::Text => Ok(text::render(report, defang).into_bytes()),
        FormatArg::Markdown => Ok(markdown::render(report, defang).into_bytes()),
    }
}

#[must_use]
pub fn options_from_args(args: &AnalyzeArgs) -> AnalyzeOptions {
    let mut options = AnalyzeOptions {
        include_strings: args.include_strings,
        ..AnalyzeOptions::default()
    };
    options.limits.min_string_len = args.min_string_len.max(1);
    if let Some(max) = args.max_strings {
        options.limits.max_strings = max;
    }
    if let Some(max) = args.max_iocs {
        options.limits.max_iocs = max;
    }
    if let Some(max) = args.max_scan_bytes {
        options.limits.max_scan_bytes = max;
    }
    options
}

use expe_core::{ArtifactReader, ExpeError, Limits, Result, StringEncoding, StringsSummary};
use expe_engine::io::FileReader;
use expe_engine::strings::scan;
use regex::Regex;

use crate::cli::{EncodingArg, StringsArgs};
use crate::commands::util;
use crate::output::text;

pub fn run(args: StringsArgs) -> Result<i32> {
    let mut limits = Limits::default();
    limits.min_string_len = args.min_len.max(1);
    let bytes = FileReader.read(&args.path, &limits)?;
    let mut result = scan(&bytes.bytes, &limits);

    if let Some(pattern) = &args.regex {
        let regex = Regex::new(pattern)
            .map_err(|error| ExpeError::Config(format!("invalid --regex: {error}")))?;
        result.items.retain(|item| regex.is_match(&item.value));
    }

    result.items.retain(|item| match args.encoding {
        EncodingArg::Both => true,
        EncodingArg::Ascii => item.encoding == StringEncoding::Ascii,
        EncodingArg::Utf16le => item.encoding == StringEncoding::Utf16Le,
    });

    let total = result.items.len();
    let shown = if args.limit == 0 {
        total
    } else {
        total.min(args.limit)
    };
    result.items.truncate(shown);

    let mut out = text::render_strings(&result.items, args.defang);
    if shown < total {
        out.push_str(&format!(
            "\n[shown {shown} of {total} matching strings; raise --limit to see more]\n"
        ));
    }
    let summary = StringsSummary {
        total: result.items.len(),
        ..StringsSummary::default()
    };
    let _ = summary;
    util::write_text(&out, args.output.as_deref())?;
    Ok(0)
}

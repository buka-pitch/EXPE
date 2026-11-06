mod cli;
mod commands;
mod output;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run() {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(2)),
        Err(error) => {
            eprintln!("expe: {error}");
            ExitCode::from(u8::try_from(error.exit_code()).unwrap_or(2))
        }
    }
}

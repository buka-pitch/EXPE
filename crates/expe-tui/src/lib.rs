//! EXPE — interactive terminal interface.
//!
//! The console is a model–view–update loop that runs a background analysis
//! worker, presents results across seven screens, and exports deterministic
//! JSON. It never executes the sample and sanitises every value that originates
//! in the file before it reaches the terminal driver.

pub mod app;
pub mod sanitize;
mod ui;
pub mod worker;

use std::io;
use std::io::{IsTerminal, Write as _};
use std::panic;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::{try_init, try_restore};

use expe_core::Result;
use expe_engine::{AnalyzeOptions, Analyzer};

use crate::app::{App, Effect, Msg};

/// Run the interactive console. If `path` is provided, analysis begins
/// immediately; otherwise the open screen is shown.
pub fn run(path: Option<PathBuf>, analyzer: Analyzer, options: &AnalyzeOptions) -> Result<()> {
    if !io::stdout().is_terminal() {
        return Err(expe_core::ExpeError::Config(
            "stdout is not a TTY; use `expe analyze --format text` instead".to_string(),
        ));
    }
    if std::env::var("TERM").as_deref() == Ok("dumb") {
        return Err(expe_core::ExpeError::Config(
            "TERM=dumb is not supported by the TUI".to_string(),
        ));
    }

    let mut terminal = try_init().map_err(|error| {
        expe_core::ExpeError::Output(format!("cannot enter alternate screen: {error}"))
    })?;
    let _guard = RestoreGuard;

    // Install a panic hook that restores the terminal before unwinding.
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = try_restore();
        previous(info);
    }));

    let mut app = App::new();
    let analyzer = Arc::new(analyzer);
    let mut worker_rx = None::<std::sync::mpsc::Receiver<crate::worker::WorkerMsg>>;

    if let Some(initial) = path {
        for effect in app.request_analysis(initial) {
            handle_effect(&effect, &mut app, &mut worker_rx, &analyzer, options);
        }
    }

    let mut last_tick = std::time::Instant::now();
    loop {
        terminal
            .draw(|frame| ui::draw(frame, &mut app))
            .map_err(|error| expe_core::ExpeError::Output(error.to_string()))?;

        // Drain worker messages before polling input.
        let mut worker_msgs = Vec::new();
        if let Some(rx) = &worker_rx {
            while let Ok(msg) = rx.try_recv() {
                worker_msgs.push(msg);
            }
        }
        for msg in worker_msgs {
            for effect in app.update(Msg::Worker(msg)) {
                handle_effect(&effect, &mut app, &mut worker_rx, &analyzer, options);
            }
        }

        // Regular tick at ~12 Hz.
        if last_tick.elapsed() >= Duration::from_millis(80) {
            for effect in app.update(Msg::Tick) {
                handle_effect(&effect, &mut app, &mut worker_rx, &analyzer, options);
            }
            last_tick = std::time::Instant::now();
        }

        if event::poll(Duration::from_millis(80))
            .map_err(|error| expe_core::ExpeError::Output(error.to_string()))?
        {
            match event::read().map_err(|error| expe_core::ExpeError::Output(error.to_string()))? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    for effect in app.update(Msg::Key(key)) {
                        handle_effect(&effect, &mut app, &mut worker_rx, &analyzer, options);
                    }
                }
                _ => {
                    // Resize events are handled by the next draw.
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn handle_effect(
    effect: &Effect,
    app: &mut App,
    worker_rx: &mut Option<std::sync::mpsc::Receiver<crate::worker::WorkerMsg>>,
    analyzer: &Arc<Analyzer>,
    options: &AnalyzeOptions,
) {
    match effect {
        Effect::Quit | Effect::CancelAnalysis => {
            *worker_rx = None;
        }
        Effect::Analyze(path) => {
            *worker_rx = Some(crate::worker::spawn(
                Arc::clone(analyzer),
                path.clone(),
                options.clone(),
            ));
        }
        Effect::Export { path, bytes } => match write_unique(path, bytes) {
            Ok(actual) => app.set_toast(
                format!("Exported {} · {} bytes", actual.display(), bytes.len()),
                crate::app::ToastKind::Good,
            ),
            Err(error) => app.set_toast(
                format!("Export failed: {error}"),
                crate::app::ToastKind::Error,
            ),
        },
        Effect::Copy(payload) => match copy_osc52(payload) {
            Ok(()) => app.set_toast("Copied to clipboard (OSC52)", crate::app::ToastKind::Good),
            Err(error) => app.set_toast(
                format!("Clipboard copy failed: {error}"),
                crate::app::ToastKind::Error,
            ),
        },
    }
}

/// Write `bytes` without silently clobbering an existing report. If `path`
/// exists, `<stem>-1.<ext>`, `<stem>-2.<ext>`, … are tried instead. Returns the
/// file that was actually created.
fn write_unique(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write as _;

    let mut candidate = path.to_path_buf();
    let mut counter = 1u32;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(bytes)?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("report");
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("json");
                let name = format!("{stem}-{counter}.{ext}");
                candidate = match parent {
                    Some(parent) => parent.join(name),
                    None => PathBuf::from(name),
                };
                counter += 1;
                if counter > 10_000 {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn copy_osc52(text: &str) -> std::io::Result<()> {
    let encoded = base64_encode(text.as_bytes());
    let mut stdout = io::stdout().lock();
    write!(stdout, "\x1b]52;c;{encoded}\x07")?;
    stdout.flush()
}

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let chunk = u32::from_be_bytes([input[i], input[i + 1], input[i + 2], 0]) >> 8;
        output.push(ALPHABET[((chunk >> 18) & 0x3F) as usize] as char);
        output.push(ALPHABET[((chunk >> 12) & 0x3F) as usize] as char);
        output.push(ALPHABET[((chunk >> 6) & 0x3F) as usize] as char);
        output.push(ALPHABET[(chunk & 0x3F) as usize] as char);
        i += 3;
    }
    let remaining = input.len() - i;
    if remaining == 1 {
        let chunk = u32::from(input[i]) << 16;
        output.push(ALPHABET[((chunk >> 18) & 0x3F) as usize] as char);
        output.push(ALPHABET[((chunk >> 12) & 0x3F) as usize] as char);
        output.push('=');
        output.push('=');
    } else if remaining == 2 {
        let chunk = (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8);
        output.push(ALPHABET[((chunk >> 18) & 0x3F) as usize] as char);
        output.push(ALPHABET[((chunk >> 12) & 0x3F) as usize] as char);
        output.push(ALPHABET[((chunk >> 6) & 0x3F) as usize] as char);
        output.push('=');
    }
    output
}

struct RestoreGuard;
impl Drop for RestoreGuard {
    fn drop(&mut self) {
        let _ = try_restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_unique_does_not_clobber() {
        let dir = std::env::temp_dir().join(format!("expe-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let first = dir.join("report.expe.json");

        let a = write_unique(&first, b"one").unwrap();
        let b = write_unique(&first, b"two").unwrap();

        assert_eq!(a, first);
        assert_eq!(b, dir.join("report.expe-1.json"));
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "one");
        assert_eq!(std::fs::read_to_string(&b).unwrap(), "two");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

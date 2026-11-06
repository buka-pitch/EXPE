//! Background analysis worker.
//!
//! Parsing is CPU-bound but deliberately isolated from the UI thread. The
//! worker reports coarse stages and sends exactly one terminal message. If the
//! UI drops the receiver (cancel, quit), sends fail silently and the thread
//! exits after the current safe parse completes.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};

use expe_core::AnalysisOutcome;
use expe_engine::{AnalyzeOptions, Analyzer, Stage};

#[derive(Debug)]
pub enum WorkerMsg {
    Stage(Stage),
    Done(Result<Box<AnalysisOutcome>, String>),
}

/// Spawn a detached analysis thread. The returned receiver is the sole UI
/// channel; dropping it is a cooperative cancellation signal.
pub fn spawn(
    analyzer: Arc<Analyzer>,
    path: PathBuf,
    options: AnalyzeOptions,
) -> Receiver<WorkerMsg> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("expe-analysis".to_string())
        .spawn(move || {
            let result = {
                let stage_tx = tx.clone();
                let mut progress = |stage| {
                    let _ = stage_tx.send(WorkerMsg::Stage(stage));
                };
                analyzer
                    .analyze_path_with_progress(&path, &options, &mut progress)
                    .map(Box::new)
                    .map_err(|error| error.to_string())
            };
            let _ = tx.send(WorkerMsg::Done(result));
        })
        .expect("cannot spawn EXPE analysis thread");
    rx
}

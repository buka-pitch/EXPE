//! EXPE analysis engine.
//!
//! The engine contains all I/O and third-party parser adapters. Hostile bytes cross
//! exactly three guarded boundaries: the size-capped reader, the panic-isolated
//! parser, and the linear-time regex engine.

pub mod entropy;
pub mod heuristics;
pub mod io;
pub mod ioc;
pub mod parse;
pub mod rules;
pub mod strings;
pub mod use_cases;

pub use use_cases::analyze::{AnalyzeOptions, Analyzer, Stage};

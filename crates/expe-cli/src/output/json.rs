use expe_core::{AnalysisReport, ExpeError, Result};

pub fn render(report: &AnalysisReport) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec_pretty(report).map_err(|error| ExpeError::Output(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[allow(dead_code)]
pub fn render_line(value: &serde_json::Value) -> Result<String> {
    serde_json::to_string(value).map_err(|error| ExpeError::Output(error.to_string()))
}

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::finding::{Category, Finding, Severity};

/// Maximum contribution of a single category. Prevents a pile of low-level
/// findings in one theme from producing an extreme score on its own.
pub const CATEGORY_CAP: u32 = 25;
const SATURATION: f64 = 40.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Low,
    Elevated,
    Suspicious,
    High,
}

impl Verdict {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Elevated => "elevated",
            Self::Suspicious => "suspicious",
            Self::High => "high",
        }
    }

    #[must_use]
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=14 => Self::Low,
            15..=39 => Self::Elevated,
            40..=69 => Self::Suspicious,
            _ => Self::High,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RiskFactor {
    pub category: Category,
    pub points: u32,
    pub capped_points: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Risk {
    pub score: u8,
    pub verdict: Verdict,
    pub factors: Vec<RiskFactor>,
}

impl Risk {
    #[must_use]
    pub fn clean() -> Self {
        Self {
            score: 0,
            verdict: Verdict::Low,
            factors: Vec::new(),
        }
    }
}

/// Deterministic, explainable score. Info findings never move the score.
#[must_use]
pub fn score_findings(findings: &[Finding]) -> Risk {
    let mut by_category: BTreeMap<Category, u32> = BTreeMap::new();
    for finding in findings {
        *by_category.entry(finding.category).or_default() += finding.severity.weight();
    }

    let factors: Vec<RiskFactor> = by_category
        .into_iter()
        .filter(|(_, points)| *points > 0)
        .map(|(category, points)| RiskFactor {
            category,
            points,
            capped_points: points.min(CATEGORY_CAP),
        })
        .collect();

    let raw: u32 = factors.iter().map(|f| f.capped_points).sum();
    let score = (100.0 * (1.0 - (-f64::from(raw) / SATURATION).exp())).round() as u8;

    Risk {
        score,
        verdict: Verdict::from_score(score),
        factors,
    }
}

/// Convenience used by callers that only need the numeric weights.
#[must_use]
pub fn severity_points(findings: &[Finding]) -> u32 {
    findings.iter().map(|f| f.severity.weight()).sum()
}

/// Highest severity in a set, if any.
#[must_use]
pub fn max_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, category: Category) -> Finding {
        Finding::new("TEST", "test", severity, category, "evidence")
    }

    #[test]
    fn empty_is_zero() {
        let risk = score_findings(&[]);
        assert_eq!(risk.score, 0);
        assert_eq!(risk.verdict, Verdict::Low);
    }

    #[test]
    fn info_does_not_score() {
        let risk = score_findings(&[finding(Severity::Info, Category::InformationLeak)]);
        assert_eq!(risk.score, 0);
    }

    #[test]
    fn category_cap_applies() {
        let findings: Vec<_> = (0..10)
            .map(|_| finding(Severity::High, Category::Packing))
            .collect();
        let risk = score_findings(&findings);
        assert_eq!(risk.factors[0].points, 120);
        assert_eq!(risk.factors[0].capped_points, CATEGORY_CAP);
    }

    #[test]
    fn score_is_bounded() {
        let findings: Vec<_> = (0..40)
            .map(|_| finding(Severity::Critical, Category::Injection))
            .collect();
        assert_eq!(score_findings(&findings).score, 46);
        let many: Vec<_> = Category::ALL
            .iter()
            .flat_map(|c| (0..10).map(move |_| finding(Severity::Critical, *c)))
            .collect();
        assert!(score_findings(&many).score <= 100);
    }

    #[test]
    fn verdict_thresholds() {
        assert_eq!(Verdict::from_score(0), Verdict::Low);
        assert_eq!(Verdict::from_score(14), Verdict::Low);
        assert_eq!(Verdict::from_score(15), Verdict::Elevated);
        assert_eq!(Verdict::from_score(40), Verdict::Suspicious);
        assert_eq!(Verdict::from_score(70), Verdict::High);
        assert_eq!(Verdict::from_score(100), Verdict::High);
    }
}

use std::collections::HashSet;
use std::path::Path;

use expe_core::{Confidence, ExpeError, IocKind, Result, Severity};
use regex::{Regex, RegexSet};
use serde::Deserialize;

const DEFAULT_RULES: &str = include_str!("../../rules/default.toml");

pub const VALIDATORS: &[&str] = &[
    "ipv4", "ipv6", "domain", "url", "email", "path", "bitcoin", "ethereum", "onion", "generic",
];

#[derive(Debug, Clone, Deserialize)]
struct RulesFile {
    #[serde(default = "default_version")]
    ruleset_version: String,
    #[serde(default)]
    rules: Vec<RuleDef>,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleDef {
    pub id: String,
    pub kind: String,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Option<Confidence>,
    pub regex: String,
    #[serde(default = "default_validator")]
    pub validator: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_validator() -> String {
    "generic".to_string()
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub def: RuleDef,
    pub kind: IocKind,
    pub regex: Regex,
}

impl CompiledRule {
    #[must_use]
    pub fn confidence(&self) -> Confidence {
        self.def.confidence.unwrap_or(Confidence::Medium)
    }
}

/// Compiled, immutable rule pack. A `RegexSet` does a single pass per candidate
/// and only matched rules run their capture regex.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub version: String,
    pub rules: Vec<CompiledRule>,
    set: RegexSet,
}

impl RuleSet {
    /// Empty pack, used when the caller explicitly disables defaults.
    pub fn empty() -> Result<Self> {
        Ok(Self {
            version: "0".to_string(),
            rules: Vec::new(),
            set: RegexSet::empty(),
        })
    }

    pub fn load_default() -> Result<Self> {
        Self::from_toml(DEFAULT_RULES, "embedded rules")
    }

    pub fn load_path(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|source| ExpeError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml(&text, &path.display().to_string())
    }

    /// Validate a rule pack without constructing a live set (used by `rules check`).
    pub fn check(text: &str) -> Result<(String, usize)> {
        let parsed = Self::from_toml(text, "rule file")?;
        Ok((parsed.version, parsed.rules.len()))
    }

    pub fn from_toml(text: &str, origin: &str) -> Result<Self> {
        let file: RulesFile =
            toml::from_str(text).map_err(|error| ExpeError::Rule(format!("{origin}: {error}")))?;
        let mut compiled = Vec::with_capacity(file.rules.len());
        let mut patterns = Vec::with_capacity(file.rules.len());
        let mut seen = HashSet::new();

        for def in file.rules {
            if !seen.insert(def.id.clone()) {
                return Err(ExpeError::Rule(format!(
                    "{origin}: duplicate rule id '{}'",
                    def.id
                )));
            }
            let kind = IocKind::parse(&def.kind).ok_or_else(|| {
                ExpeError::Rule(format!(
                    "{origin}: rule '{}' has unknown kind '{}'",
                    def.id, def.kind
                ))
            })?;
            if !VALIDATORS.contains(&def.validator.as_str()) {
                return Err(ExpeError::Rule(format!(
                    "{origin}: rule '{}' uses unknown validator '{}'",
                    def.id, def.validator
                )));
            }
            let regex = Regex::new(&def.regex).map_err(|error| {
                ExpeError::Rule(format!("{origin}: rule '{}': {error}", def.id))
            })?;
            patterns.push(def.regex.clone());
            compiled.push(CompiledRule { def, kind, regex });
        }

        let set = RegexSet::new(&patterns)
            .map_err(|error| ExpeError::Rule(format!("{origin}: {error}")))?;
        Ok(Self {
            version: file.ruleset_version,
            rules: compiled,
            set,
        })
    }

    /// Merge a user pack into this one. Rules with the same id are replaced.
    pub fn merge(&self, user: &Self) -> Result<Self> {
        let mut by_id: Vec<CompiledRule> = self.rules.clone();
        for rule in &user.rules {
            if let Some(existing) = by_id
                .iter_mut()
                .find(|existing| existing.def.id == rule.def.id)
            {
                *existing = rule.clone();
            } else {
                by_id.push(rule.clone());
            }
        }
        let patterns: Vec<String> = by_id.iter().map(|rule| rule.def.regex.clone()).collect();
        let set = RegexSet::new(&patterns)
            .map_err(|error| ExpeError::Rule(format!("merged rules: {error}")))?;
        Ok(Self {
            version: if user.version.is_empty() {
                self.version.clone()
            } else {
                user.version.clone()
            },
            rules: by_id,
            set,
        })
    }

    /// Rule indices matching a candidate string.
    #[must_use]
    pub fn matching(&self, candidate: &str) -> Vec<usize> {
        self.set.matches(candidate).iter().collect()
    }

    #[must_use]
    pub fn rule(&self, index: usize) -> Option<&CompiledRule> {
        self.rules.get(index)
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::load_default().expect("embedded rule pack must compile")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pack_compiles() {
        let rules = RuleSet::load_default().unwrap();
        assert_eq!(rules.version, "1.0.0");
        assert!(rules.rules.len() >= 13);
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let error = RuleSet::from_toml(
            r#"
            ruleset_version = "x"
            [[rules]]
            id = "bad"
            kind = "nope"
            severity = "low"
            regex = "a"
            "#,
            "test",
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown kind"));
    }

    #[test]
    fn duplicate_id_is_rejected() {
        let error = RuleSet::from_toml(
            r#"
            [[rules]]
            id = "dup"
            kind = "ipv4"
            severity = "low"
            regex = "a"
            [[rules]]
            id = "dup"
            kind = "domain"
            severity = "low"
            regex = "b"
            "#,
            "test",
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn override_replaces_by_id() {
        let base = RuleSet::load_default().unwrap();
        let user = RuleSet::from_toml(
            r#"
            ruleset_version = "2.0.0"
            [[rules]]
            id = "ioc.domain"
            kind = "domain"
            severity = "medium"
            regex = "example\\.test"
            "#,
            "user",
        )
        .unwrap();
        let merged = base.merge(&user).unwrap();
        assert_eq!(merged.version, "2.0.0");
        let domain = merged
            .rules
            .iter()
            .find(|rule| rule.def.id == "ioc.domain")
            .unwrap();
        assert_eq!(domain.def.severity, Severity::Medium);
    }
}

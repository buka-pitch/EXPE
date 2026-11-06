use std::collections::{BTreeMap, HashMap};

use expe_core::{
    Confidence, ExtractedString, Ioc, IocGroup, IocKind, IocSource, IpScope, Limits, Structure,
    defang,
};

use super::validate::validate;
use crate::rules::RuleSet;

#[derive(Debug, Clone, Default)]
pub struct IocResult {
    pub groups: Vec<IocGroup>,
    pub truncated: bool,
}

pub struct IocExtractor<'a> {
    rules: &'a RuleSet,
}

impl<'a> IocExtractor<'a> {
    #[must_use]
    pub fn new(rules: &'a RuleSet) -> Self {
        Self { rules }
    }

    #[must_use]
    pub fn extract(
        &self,
        strings: &[ExtractedString],
        structure: &Structure,
        limits: &Limits,
    ) -> IocResult {
        let mut state = State {
            rules: self.rules,
            limits,
            groups: HashMap::new(),
            index: HashMap::new(),
            total: 0,
            truncated: false,
        };

        for string in strings {
            state.ingest(&string.value, IocSource::Strings, string.offset);
        }

        match structure {
            Structure::Pe(pe) => {
                for section in &pe.sections {
                    state.ingest(&section.name, IocSource::SectionNames, section.raw_offset);
                }
                for library in &pe.imports {
                    state.ingest(&library.dll, IocSource::Imports, 0);
                    for function in &library.functions {
                        state.ingest(&function.name, IocSource::Imports, function.offset);
                    }
                }
                for export in &pe.exports {
                    state.ingest(&export.name, IocSource::Exports, export.offset.unwrap_or(0));
                }
                if let Some(pdb) = &pe.debug_pdb {
                    state.ingest(pdb, IocSource::Debug, 0);
                }
                for value in pe.version_info.values() {
                    state.ingest(value, IocSource::VersionInfo, 0);
                }
                if let Some(overlay) = &pe.overlay {
                    for signature in &overlay.embedded {
                        let kind = match signature.as_str() {
                            "PE" => Some(IocKind::EmbeddedPe),
                            "ELF" => Some(IocKind::EmbeddedElf),
                            _ => None,
                        };
                        if let Some(kind) = kind {
                            state.insert_embedded(
                                kind,
                                &format!("embedded {signature}"),
                                overlay.offset,
                            );
                        }
                    }
                }
            }
            Structure::Elf(elf) => {
                for section in &elf.sections {
                    state.ingest(&section.name, IocSource::SectionNames, section.raw_offset);
                }
                for library in &elf.libraries {
                    state.ingest(library, IocSource::Imports, 0);
                }
                for symbol in &elf.symbols {
                    state.ingest(symbol, IocSource::Exports, 0);
                }
                for path in elf.rpaths.iter().chain(&elf.runpaths) {
                    state.ingest(path, IocSource::Strings, 0);
                }
                if let Some(interpreter) = &elf.interpreter {
                    state.ingest(interpreter, IocSource::Strings, 0);
                }
            }
            Structure::MachO(macho) => {
                for library in &macho.libraries {
                    state.ingest(library, IocSource::Imports, 0);
                }
                for segment in &macho.segments {
                    state.ingest(&segment.name, IocSource::SectionNames, segment.file_offset);
                }
            }
            Structure::Unavailable => {}
        }

        let mut groups: Vec<IocGroup> = BTreeMap::from_iter(state.groups)
            .into_iter()
            .map(|(kind, mut items)| {
                items.sort_by(|a, b| a.value.cmp(&b.value));
                for item in &mut items {
                    item.offsets.sort_unstable();
                    item.offsets.dedup();
                    item.sources.sort_unstable();
                    item.sources.dedup();
                }
                IocGroup { kind, items }
            })
            .filter(|group| !group.items.is_empty())
            .collect();
        groups.sort_by_key(|group| group.kind);

        IocResult {
            groups,
            truncated: state.truncated,
        }
    }
}

struct State<'a> {
    rules: &'a RuleSet,
    limits: &'a Limits,
    groups: HashMap<IocKind, Vec<Ioc>>,
    index: HashMap<(IocKind, String), usize>,
    total: usize,
    truncated: bool,
}

impl State<'_> {
    fn ingest(&mut self, value: &str, source: IocSource, offset: u64) {
        if value.len() < 3 || self.total >= self.limits.max_iocs {
            if self.total >= self.limits.max_iocs {
                self.truncated = true;
            }
            return;
        }

        // Collect first to avoid holding an immutable borrow of `rules` across insert.
        let mut found: Vec<(usize, String, usize)> = Vec::new();
        for rule_index in self.rules.matching(value) {
            let Some(rule) = self.rules.rule(rule_index) else {
                continue;
            };
            for captures in rule.regex.captures_iter(value) {
                if let Some(matched) = captures.get(1).or_else(|| captures.get(0)) {
                    found.push((rule_index, matched.as_str().to_string(), matched.start()));
                }
            }
        }

        for (rule_index, candidate, start) in found {
            let Some(rule) = self.rules.rule(rule_index) else {
                continue;
            };
            let validator = rule.def.validator.clone();
            let Some(mut valid) = validate(&validator, &candidate) else {
                continue;
            };
            if valid.value.is_empty() {
                continue;
            }
            valid.value = valid.value.trim().to_string();
            let mut confidence = rule.confidence();
            if matches!(rule.kind, IocKind::Ipv4 | IocKind::Ipv6) {
                confidence = match valid.scope {
                    Some(IpScope::Public) => Confidence::Medium,
                    _ => Confidence::Low,
                };
            }
            self.insert(
                rule.kind,
                valid.value,
                valid.scope,
                source,
                offset.saturating_add(start as u64),
                confidence,
                Some(rule.def.id.clone()),
            );
        }
    }

    fn insert_embedded(&mut self, kind: IocKind, value: &str, offset: u64) {
        self.insert(
            kind,
            value.to_string(),
            None,
            IocSource::Overlay,
            offset,
            Confidence::High,
            Some("overlay.embedded".to_string()),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        kind: IocKind,
        value: String,
        scope: Option<IpScope>,
        source: IocSource,
        offset: u64,
        confidence: Confidence,
        rule_id: Option<String>,
    ) {
        let key = (kind, value.clone());
        if let Some(&position) = self.index.get(&key) {
            if let Some(item) = self
                .groups
                .get_mut(&kind)
                .and_then(|items| items.get_mut(position))
            {
                if !item.sources.contains(&source) {
                    item.sources.push(source);
                }
                if item.offsets.len() < 16 && !item.offsets.contains(&offset) {
                    item.offsets.push(offset);
                }
                item.occurrences = item.occurrences.saturating_add(1);
                if confidence_rank(confidence) > confidence_rank(item.confidence) {
                    item.confidence = confidence;
                }
                if item.scope.is_none() {
                    item.scope = scope;
                }
            }
            return;
        }

        if self.total >= self.limits.max_iocs {
            self.truncated = true;
            return;
        }

        let items = self.groups.entry(kind).or_default();
        let position = items.len();
        items.push(Ioc {
            kind,
            defanged: defang(&value, kind),
            value,
            sources: vec![source],
            offsets: vec![offset],
            occurrences: 1,
            confidence,
            scope,
            rule_id,
        });
        self.index.insert(key, position);
        self.total += 1;
    }
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

#[cfg(test)]
mod tests {
    use expe_core::{StringEncoding, Structure};

    use super::*;

    fn string(value: &str, offset: u64) -> ExtractedString {
        ExtractedString {
            value: value.to_string(),
            offset,
            encoding: StringEncoding::Ascii,
            occurrences: 1,
            truncated: false,
        }
    }

    #[test]
    fn extracts_and_dedupes() {
        let rules = RuleSet::load_default().unwrap();
        let extractor = IocExtractor::new(&rules);
        let strings = vec![
            string("connect to evil.example.com", 10),
            string("http://evil.example.com/dropper.bin", 100),
            string("c2 185.10.20.30:443", 200),
            string("192.168.1.10", 300),
        ];
        let result = extractor.extract(&strings, &Structure::Unavailable, &Limits::default());
        assert!(result.groups.iter().any(|g| g.kind == IocKind::Domain));
        let domains = result
            .groups
            .iter()
            .find(|g| g.kind == IocKind::Domain)
            .unwrap();
        assert_eq!(domains.items[0].value, "evil.example.com");
        assert_eq!(domains.items[0].occurrences, 2);
        assert!(result.groups.iter().any(|g| g.kind == IocKind::Url));
        let ips = result
            .groups
            .iter()
            .find(|g| g.kind == IocKind::Ipv4)
            .unwrap();
        assert_eq!(ips.items.len(), 2);
        assert_eq!(ips.items[0].scope, Some(IpScope::Public));
        assert_eq!(ips.items[1].scope, Some(IpScope::Private));
    }

    #[test]
    fn defangs_urls() {
        let rules = RuleSet::load_default().unwrap();
        let extractor = IocExtractor::new(&rules);
        let result = extractor.extract(
            &[string("http://evil.test/a", 0)],
            &Structure::Unavailable,
            &Limits::default(),
        );
        let url = &result
            .groups
            .iter()
            .find(|g| g.kind == IocKind::Url)
            .unwrap()
            .items[0];
        assert_eq!(url.defanged, "hxxp://evil[.]test/a");
    }

    #[test]
    fn respects_ioc_cap() {
        let rules = RuleSet::load_default().unwrap();
        let extractor = IocExtractor::new(&rules);
        let limits = Limits {
            max_iocs: 1,
            ..Limits::default()
        };
        let strings = vec![string("1.2.3.4", 0), string("5.6.7.8", 10)];
        let result = extractor.extract(&strings, &Structure::Unavailable, &limits);
        assert_eq!(
            result.groups.iter().map(|g| g.items.len()).sum::<usize>(),
            1
        );
        assert!(result.truncated);
    }
}

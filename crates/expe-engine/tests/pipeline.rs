use expe_core::{Format, IocKind};
use expe_engine::{AnalyzeOptions, Analyzer};
use expe_testkit::strings_pe;

#[test]
fn end_to_end_pe_analysis() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sample.exe");
    std::fs::write(&path, strings_pe()).unwrap();

    let analyzer = Analyzer::with_default_rules().unwrap();
    let outcome = analyzer
        .analyze_path(&path, &AnalyzeOptions::default())
        .unwrap();
    assert!(outcome.raw.is_some());
    let report = outcome.report;

    assert_eq!(report.artifact.format, Format::Pe);
    assert_eq!(report.artifact.file_name, "sample.exe");
    assert_eq!(report.artifact.hashes.sha256.len(), 64);
    assert!(report.artifact.entropy > 0.0);

    let kinds: Vec<IocKind> = report.iocs.iter().map(|group| group.kind).collect();
    assert!(kinds.contains(&IocKind::Domain));
    assert!(kinds.contains(&IocKind::Url));
    assert!(kinds.contains(&IocKind::Ipv4));
    assert!(kinds.contains(&IocKind::RegistryKey));
    assert!(kinds.contains(&IocKind::PdbPath));

    let domain = report
        .iocs
        .iter()
        .find(|group| group.kind == IocKind::Domain)
        .unwrap();
    assert!(
        domain
            .items
            .iter()
            .any(|ioc| ioc.value == "malicious.example.com")
    );
}

#[test]
fn packed_fixture_scores_as_suspicious() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("packed.exe");
    std::fs::write(&path, expe_testkit::packed_pe()).unwrap();

    let analyzer = Analyzer::with_default_rules().unwrap();
    let report = analyzer
        .analyze_path(&path, &AnalyzeOptions::default())
        .unwrap()
        .report;

    assert!(report.risk.score > 0);
    assert!(report.findings.iter().any(|f| f.id == "PE_PACKER_SECTION"));
}

#[test]
fn archive_is_rejected_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sample.zip");
    std::fs::write(&path, b"PK\x03\x04not really a zip").unwrap();
    let analyzer = Analyzer::with_default_rules().unwrap();
    let error = analyzer
        .analyze_path(&path, &AnalyzeOptions::default())
        .unwrap_err();
    assert!(error.to_string().contains("archive"));
}

#[test]
fn bytes_entry_point_matches_path_entry_point() {
    let bytes = strings_pe();
    let analyzer = Analyzer::with_default_rules().unwrap();
    let from_bytes = analyzer
        .analyze_bytes(
            "memory.exe",
            bytes.clone().into(),
            &AnalyzeOptions::default(),
        )
        .unwrap();
    assert_eq!(from_bytes.report.artifact.file_name, "memory.exe");
    assert_eq!(from_bytes.report.artifact.size, bytes.len() as u64);
}

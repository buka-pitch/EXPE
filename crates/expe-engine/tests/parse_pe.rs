use expe_core::{Format, Limits, Structure};
use expe_engine::parse::{detect, parse_structure};
use expe_testkit::{CHARACTERISTICS_READ_WRITE_EXECUTE, PeBuilder, minimal_pe, packed_pe};

#[test]
fn parses_minimal_pe() {
    let bytes = minimal_pe();
    assert_eq!(detect(&bytes), Format::Pe);
    let structure = parse_structure(&bytes, Format::Pe, &Limits::default()).unwrap();
    let Structure::Pe(pe) = structure else {
        panic!("expected PE");
    };
    assert_eq!(pe.machine, "x86_64");
    assert_eq!(pe.subsystem, "console");
    assert!(pe.is_64);
    assert_eq!(pe.sections.len(), 1);
    assert_eq!(pe.sections[0].name, ".text");
    assert_eq!(pe.sections[0].permissions, "R-X");
    assert_eq!(pe.entry_point, 0x1_4000_1000);
    assert!(pe.overlay.is_none());
    assert_eq!(pe.timestamp, 1_700_000_000);
    assert!(pe.timestamp_iso.is_some());
}

#[test]
fn detects_rwx_section_flags() {
    let bytes = PeBuilder::new()
        .section_with_flags(".evil", vec![0x90; 64], CHARACTERISTICS_READ_WRITE_EXECUTE)
        .build();
    let structure = parse_structure(&bytes, Format::Pe, &Limits::default()).unwrap();
    let Structure::Pe(pe) = structure else {
        panic!("expected PE");
    };
    assert!(
        pe.sections
            .iter()
            .any(|section| section.name == ".evil" && section.permissions == "RWX")
    );
}

#[test]
fn detects_overlay_and_embedded_pe() {
    let nested = minimal_pe();
    let mut overlay = b"padding".to_vec();
    overlay.extend_from_slice(&nested);
    let bytes = PeBuilder::new().overlay(overlay).build();
    let structure = parse_structure(&bytes, Format::Pe, &Limits::default()).unwrap();
    let Structure::Pe(pe) = structure else {
        panic!("expected PE");
    };
    let overlay = pe.overlay.expect("overlay");
    assert!(overlay.size > 0);
    assert!(overlay.embedded.iter().any(|value| value == "PE"));
}

#[test]
fn parses_packer_sections() {
    let structure = parse_structure(&packed_pe(), Format::Pe, &Limits::default()).unwrap();
    let Structure::Pe(pe) = structure else {
        panic!("expected PE");
    };
    assert!(pe.sections.iter().any(|section| section.name == "UPX0"));
    assert!(pe.sections.iter().any(|section| section.name == "UPX1"));
}

#[test]
fn truncated_pe_errors_without_panicking() {
    let bytes = minimal_pe();
    let truncated = &bytes[..0x60];
    let result = parse_structure(truncated, Format::Pe, &Limits::default());
    assert!(result.is_err());
}

//! winevt-core integrity anomalies normalize onto the canonical
//! `forensicnomicon::report` model via the `Observation` producer trait.

use forensicnomicon::report::{Observation, Source};
use winevt_core::binary::IntegrityAnomaly;

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = IntegrityAnomaly::ChecksumMismatch;
    let f = a.to_finding(Source {
        analyzer: "winevt-forensic".to_string(),
        scope: "EVTX".to_string(),
        version: None,
    });
    assert_eq!(f.code, "WINEVT-CHECKSUM-MISMATCH");
    assert!(f.severity.is_some());
}

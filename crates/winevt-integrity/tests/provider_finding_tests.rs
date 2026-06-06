//! ProviderAnomaly normalizes onto the canonical `forensicnomicon::report` model.

use forensicnomicon::report::{Observation, Severity, Source};
use winevt_integrity::ProviderAnomaly;

#[test]
fn provider_anomaly_converts_to_a_canonical_finding() {
    let a = ProviderAnomaly::GuidSpoofing {
        provider_name: "Microsoft-Windows-Security-Auditing".to_string(),
        expected_guid: [0u8; 16],
        actual_guid: [1u8; 16],
    };
    let f = a.to_finding(Source {
        analyzer: "winevt-forensic".to_string(),
        scope: "provider".to_string(),
        version: None,
    });
    assert_eq!(f.code, "WINEVT-PROVIDER-GUID-SPOOFING");
    assert_eq!(f.severity, Some(Severity::High));
    assert!(f.evidence.iter().any(|e| e.field == "provider_name"));
}

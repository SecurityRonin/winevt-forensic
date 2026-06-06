use winevt_core::binary::{IntegrityAnomaly, Severity};
use winevt_integrity::{detect_phantom_records, phantom_alerts_to_anomalies, WinevtIntegrity};

// ── Minimum container size guard ─────────────────────────────────────────────

#[test]
fn analyse_empty_buffer_returns_truncated_file() {
    let anomalies = WinevtIntegrity::analyse(&[]);
    assert!(
        !anomalies.is_empty(),
        "empty buffer must produce at least one anomaly"
    );
    let has_truncated = anomalies.iter().any(|a| matches!(a, IntegrityAnomaly::TruncatedFile { .. }));
    assert!(has_truncated, "empty buffer must produce TruncatedFile; got {:?}", anomalies);
}

#[test]
fn analyse_sub_128_buffer_returns_truncated_file() {
    let buf = vec![0u8; 64];
    let anomalies = WinevtIntegrity::analyse(&buf);
    assert!(
        !anomalies.is_empty(),
        "buffer < 128 bytes must produce at least one anomaly"
    );
    let has_truncated = anomalies.iter().any(|a| matches!(a, IntegrityAnomaly::TruncatedFile { .. }));
    assert!(has_truncated, "buffer < 128 bytes must produce TruncatedFile; got {:?}", anomalies);
}

#[test]
fn analyse_truncated_anomaly_is_error_severity() {
    let anomalies = WinevtIntegrity::analyse(&[]);
    let truncated = anomalies.iter().find(|a| matches!(a, IntegrityAnomaly::TruncatedFile { .. }));
    let a = truncated.expect("TruncatedFile must be present");
    assert_eq!(a.severity(), Severity::High);
}

// ── EmptyLog variant ──────────────────────────────────────────────────────────

#[test]
fn empty_log_variant_exists_and_debug() {
    let a = IntegrityAnomaly::EmptyLog;
    let s = format!("{a:?}");
    assert!(s.contains("EmptyLog"));
}

#[test]
fn empty_log_severity_is_warning() {
    assert_eq!(IntegrityAnomaly::EmptyLog.severity(), Severity::Medium);
}

#[test]
fn analyse_detects_empty_log_when_chunk_count_zero() {
    // Build a valid 128-byte EVTX file header with chunk_count = 0 and correct magic.
    // The EVTX file header magic is ElfFile\0 (8 bytes).
    use winevt_core::binary::ELFFILE_MAGIC;
    let mut buf = vec![0u8; 128];
    buf[0..8].copy_from_slice(&ELFFILE_MAGIC);
    // chunk_count at bytes [42..44] — leave as 0 (already zero-initialised)
    let anomalies = WinevtIntegrity::analyse(&buf);
    let has_empty_log = anomalies.iter().any(|a| matches!(a, IntegrityAnomaly::EmptyLog));
    assert!(has_empty_log, "zero chunk_count must produce EmptyLog; got {:?}", anomalies);
}

// ── PhantomRecordInjection ────────────────────────────────────────────────────

#[test]
fn phantom_record_injection_variant_exists() {
    let a = IntegrityAnomaly::PhantomRecordInjection {
        gap_start_id: 2,
        gap_end_id: 99,
        prev_timestamp_ns: 0,
        next_timestamp_ns: 100,
    };
    assert!(format!("{a:?}").contains("PhantomRecordInjection"));
}

#[test]
fn phantom_record_injection_severity_is_error() {
    let a = IntegrityAnomaly::PhantomRecordInjection {
        gap_start_id: 2,
        gap_end_id: 99,
        prev_timestamp_ns: 0,
        next_timestamp_ns: 100,
    };
    assert_eq!(a.severity(), Severity::High);
}

#[test]
fn suspicious_phantom_alerts_convert_to_phantom_record_injection() {
    // Gap: IDs jump 1→1000 (998 missing), but only 100 ns elapsed.
    // 100 ns / 998 ≈ 0.1 ns per missing record — far below 1 ms threshold → suspicious.
    let records = [(1u64, 0i64), (1000u64, 100i64)];
    let alerts = detect_phantom_records(&records);
    assert!(!alerts.is_empty(), "should detect suspicious gap");
    assert!(alerts[0].suspicious, "gap must be flagged suspicious");

    let anomalies = phantom_alerts_to_anomalies(&alerts);
    assert!(
        anomalies.iter().any(|a| matches!(a, IntegrityAnomaly::PhantomRecordInjection { .. })),
        "suspicious alerts must produce PhantomRecordInjection; got {:?}", anomalies
    );
}

#[test]
fn benign_gap_does_not_produce_phantom_record_injection() {
    // Gap: IDs jump 1→100 (98 missing), 500 ms elapsed → 5.1 ms per record → benign.
    let records = [(1u64, 0i64), (100u64, 500_000_000i64)];
    let alerts = detect_phantom_records(&records);
    let anomalies = phantom_alerts_to_anomalies(&alerts);
    assert!(
        !anomalies.iter().any(|a| matches!(a, IntegrityAnomaly::PhantomRecordInjection { .. })),
        "benign gap must not produce PhantomRecordInjection"
    );
}

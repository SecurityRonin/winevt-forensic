/// Anomaly detected when an event's provider metadata is inconsistent with its content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum ProviderAnomaly {
    /// The event ID is not in the expected set for this provider GUID.
    UnexpectedEventId {
        provider_name: String,
        event_id: u32,
    },
    /// The provider name matches a known provider, but the GUID does not.
    GuidSpoofing {
        provider_name: String,
        expected_guid: [u8; 16],
        actual_guid: [u8; 16],
    },
    /// The channel does not match the expected channel for this provider.
    ChannelMismatch {
        provider_name: String,
        expected_channel: String,
        actual_channel: String,
    },
}

struct KnownProvider {
    name: &'static str,
    guid: [u8; 16],
    channel: &'static str,
    event_ids: &'static [u32],
}

// GUID bytes are stored in the byte order Windows uses (mixed-endian GUID on disk):
// {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} → [u8; 16] little-endian parts 1-3, big-endian part 4-5.
// We store them as the raw 16 bytes in the order the field appears in BinXML.
const KNOWN_PROVIDERS: &[KnownProvider] = &[
    KnownProvider {
        name: "Microsoft-Windows-Security-Auditing",
        // {54849625-5478-4994-A5BA-3E3B0328C30D}
        guid: [
            0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28,
            0xC3, 0x0D,
        ],
        channel: "Security",
        event_ids: &[
            1100, 1102, 1104, 4608, 4616, 4624, 4625, 4634, 4647, 4648, 4649, 4656, 4657, 4660,
            4663, 4670, 4672, 4673, 4674, 4688, 4689, 4698, 4699, 4700, 4702, 4719, 4720, 4722,
            4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4740, 4741, 4742, 4743, 4756, 4757,
            4767, 4768, 4769, 4770, 4771, 4776, 4798, 4799,
        ],
    },
    KnownProvider {
        name: "Microsoft-Windows-PowerShell",
        // {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
        guid: [
            0x3B, 0x85, 0xC1, 0xA0, 0x40, 0x5C, 0x15, 0x4B, 0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F,
            0x98, 0x5A,
        ],
        channel: "Microsoft-Windows-PowerShell/Operational",
        event_ids: &[4100, 4103, 4104, 4105, 4106],
    },
    KnownProvider {
        name: "Microsoft-Windows-Sysmon",
        // {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
        guid: [
            0x5F, 0x38, 0x70, 0x57, 0x2A, 0xC2, 0xE0, 0x43, 0xBF, 0x4C, 0x06, 0xF5, 0x69, 0x8F,
            0xFB, 0xD9,
        ],
        channel: "Microsoft-Windows-Sysmon/Operational",
        event_ids: &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29,
        ],
    },
    KnownProvider {
        name: "Microsoft-Windows-TaskScheduler",
        // {DE7B24EA-73C8-4A09-985D-5BDADCFA9017}
        guid: [
            0xEA, 0x24, 0x7B, 0xDE, 0xC8, 0x73, 0x09, 0x4A, 0x98, 0x5D, 0x5B, 0xDA, 0xDC, 0xFA,
            0x90, 0x17,
        ],
        channel: "Microsoft-Windows-TaskScheduler/Operational",
        event_ids: &[
            100, 101, 102, 103, 104, 106, 107, 108, 110, 111, 118, 119, 120, 121, 122, 123, 124,
            125, 126, 127, 129, 130, 140, 141, 200, 201, 202, 203,
        ],
    },
];

/// Check provider metadata consistency for a single event.
///
/// `provider_guid` is the 16-byte GUID as it appears in the BinXML data.
/// If `None`, only the name-based checks are performed.
///
/// Checks:
/// 1. If `provider_name` is in the known table: verify GUID matches.
/// 2. If GUID matches a known table entry: verify `event_id` is expected.
/// 3. If GUID matches a known table entry: verify `channel` matches.
pub fn check_provider_consistency(
    provider_name: &str,
    provider_guid: Option<&[u8; 16]>,
    event_id: u32,
    channel: &str,
) -> Vec<ProviderAnomaly> {
    let mut out = Vec::new();

    // Find entry by name
    let by_name = KNOWN_PROVIDERS
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(provider_name));

    // Find entry by GUID
    let by_guid = provider_guid.and_then(|g| KNOWN_PROVIDERS.iter().find(|p| &p.guid == g));

    // 1. Provider name matches known entry — check GUID
    if let (Some(entry), Some(guid)) = (by_name, provider_guid) {
        if &entry.guid != guid {
            out.push(ProviderAnomaly::GuidSpoofing {
                provider_name: provider_name.to_string(),
                expected_guid: entry.guid,
                actual_guid: *guid,
            });
        }
    }

    // 2 & 3. GUID matches known entry — check event_id and channel
    if let Some(entry) = by_guid {
        if !entry.event_ids.contains(&event_id) {
            out.push(ProviderAnomaly::UnexpectedEventId {
                provider_name: entry.name.to_string(),
                event_id,
            });
        }
        if !entry.channel.eq_ignore_ascii_case(channel) {
            out.push(ProviderAnomaly::ChannelMismatch {
                provider_name: entry.name.to_string(),
                expected_channel: entry.channel.to_string(),
                actual_channel: channel.to_string(),
            });
        }
    }

    out
}

impl forensicnomicon::report::Observation for ProviderAnomaly {
    fn severity(&self) -> Option<forensicnomicon::report::Severity> {
        use forensicnomicon::report::Severity;
        Some(match self {
            ProviderAnomaly::GuidSpoofing { .. } => Severity::High,
            ProviderAnomaly::ChannelMismatch { .. } => Severity::Medium,
            ProviderAnomaly::UnexpectedEventId { .. } => Severity::Low,
        })
    }

    fn category(&self) -> forensicnomicon::report::Category {
        use forensicnomicon::report::Category;
        match self {
            ProviderAnomaly::GuidSpoofing { .. } => Category::Concealment,
            ProviderAnomaly::ChannelMismatch { .. } => Category::Structure,
            ProviderAnomaly::UnexpectedEventId { .. } => Category::Provenance,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ProviderAnomaly::UnexpectedEventId { .. } => "WINEVT-PROVIDER-UNEXPECTED-EVENTID",
            ProviderAnomaly::GuidSpoofing { .. } => "WINEVT-PROVIDER-GUID-SPOOFING",
            ProviderAnomaly::ChannelMismatch { .. } => "WINEVT-PROVIDER-CHANNEL-MISMATCH",
        }
    }

    fn note(&self) -> String {
        match self {
            ProviderAnomaly::UnexpectedEventId {
                provider_name,
                event_id,
            } => {
                format!(
                    "event ID {event_id} is not in the expected set for provider '{provider_name}'"
                )
            }
            ProviderAnomaly::GuidSpoofing { provider_name, .. } => {
                format!("provider name '{provider_name}' matches a known provider but its GUID does not")
            }
            ProviderAnomaly::ChannelMismatch {
                provider_name,
                expected_channel,
                actual_channel,
            } => {
                format!("provider '{provider_name}' logged to '{actual_channel}', expected '{expected_channel}'")
            }
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            ProviderAnomaly::GuidSpoofing { .. } => &["T1036"],
            _ => &[],
        }
    }

    fn evidence(&self) -> Vec<forensicnomicon::report::Evidence> {
        let ev = |field: &str, value: String| forensicnomicon::report::Evidence {
            field: field.to_string(),
            value,
            location: None,
        };
        let hex = |g: &[u8; 16]| {
            use std::fmt::Write as _;
            g.iter().fold(String::with_capacity(32), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            })
        };
        match self {
            ProviderAnomaly::UnexpectedEventId {
                provider_name,
                event_id,
            } => vec![
                ev("provider_name", provider_name.clone()),
                ev("event_id", event_id.to_string()),
            ],
            ProviderAnomaly::GuidSpoofing {
                provider_name,
                expected_guid,
                actual_guid,
            } => vec![
                ev("provider_name", provider_name.clone()),
                ev("expected_guid", hex(expected_guid)),
                ev("actual_guid", hex(actual_guid)),
            ],
            ProviderAnomaly::ChannelMismatch {
                provider_name,
                expected_channel,
                actual_channel,
            } => vec![
                ev("provider_name", provider_name.clone()),
                ev("expected_channel", expected_channel.clone()),
                ev("actual_channel", actual_channel.clone()),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security_guid() -> [u8; 16] {
        [
            0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28,
            0xC3, 0x0D,
        ]
    }

    #[test]
    fn known_provider_valid_event_id_no_anomaly() {
        let g = security_guid();
        let result = check_provider_consistency(
            "Microsoft-Windows-Security-Auditing",
            Some(&g),
            4624,
            "Security",
        );
        assert!(
            result.is_empty(),
            "valid provider/EID/channel must produce no anomalies; got {result:?}"
        );
    }

    #[test]
    fn known_provider_unexpected_event_id_flagged() {
        let g = security_guid();
        let result = check_provider_consistency(
            "Microsoft-Windows-Security-Auditing",
            Some(&g),
            9999, // not in the expected set
            "Security",
        );
        assert!(
            result
                .iter()
                .any(|a| matches!(a, ProviderAnomaly::UnexpectedEventId { event_id: 9999, .. })),
            "unexpected EID must be flagged; got {result:?}"
        );
    }

    #[test]
    fn provider_name_guid_mismatch_flagged() {
        let wrong_guid = [0x00u8; 16];
        let result = check_provider_consistency(
            "Microsoft-Windows-Security-Auditing",
            Some(&wrong_guid),
            4624,
            "Security",
        );
        assert!(
            result
                .iter()
                .any(|a| matches!(a, ProviderAnomaly::GuidSpoofing { .. })),
            "GUID mismatch must be flagged; got {result:?}"
        );
    }

    #[test]
    fn unknown_provider_passes_unchecked() {
        let result = check_provider_consistency("MyCustomApp", None, 1234, "Application");
        assert!(
            result.is_empty(),
            "unknown provider must produce no anomalies"
        );
    }

    #[test]
    fn channel_mismatch_flagged() {
        let g = security_guid();
        let result = check_provider_consistency(
            "Microsoft-Windows-Security-Auditing",
            Some(&g),
            4624,
            "Application", // wrong channel
        );
        assert!(
            result
                .iter()
                .any(|a| matches!(a, ProviderAnomaly::ChannelMismatch { .. })),
            "wrong channel must be flagged; got {result:?}"
        );
    }

    #[test]
    fn no_guid_provided_name_only_checks_skipped() {
        // Without a GUID, name-based GUID check can't run, and GUID-based checks can't run.
        // For a known provider with no GUID provided, no anomalies.
        let result = check_provider_consistency(
            "Microsoft-Windows-Security-Auditing",
            None,
            9999,
            "Security",
        );
        assert!(result.is_empty(), "no GUID → no anomalies; got {result:?}");
    }
}

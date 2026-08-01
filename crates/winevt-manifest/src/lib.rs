#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
use std::collections::HashMap;
use std::path::Path;

mod bundled;
mod xml_loader;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("XML parse error: {0}")]
    Xml(String),
}

/// Maps `(normalized_provider_guid, event_id)` to an ordered list of field names.
///
/// Field names correspond to positions in the BinXML substitution array; the EVTX
/// parser emits them as `Param1`, `Param2`, … when no manifest is available at
/// decode time. `resolve_fields` replaces those anonymous names with the actual
/// names declared in the provider's `<template>` element.
pub struct ManifestDb {
    templates: HashMap<(String, u32), Vec<String>>,
}

impl ManifestDb {
    pub fn new() -> Self {
        ManifestDb {
            templates: HashMap::new(),
        }
    }

    /// Load the bundled snapshot of the 30 most common Microsoft provider manifests.
    pub fn load_bundled() -> Self {
        let mut db = ManifestDb::new();
        for (guid, event_id, fields) in bundled::ENTRIES {
            let key = (normalize_guid(guid), *event_id);
            db.templates
                .insert(key, fields.iter().map(|s| s.to_string()).collect());
        }
        db
    }

    /// Parse all `.man` XML files in `dir` and merge their template definitions.
    pub fn load_from_directory(dir: &Path) -> Result<Self, ManifestError> {
        let mut db = ManifestDb::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("man") {
                let content = std::fs::read_to_string(&path)?;
                xml_loader::load_into(&content, &mut db.templates)
                    .map_err(|e| ManifestError::Xml(e.to_string()))?;
            }
        }
        Ok(db)
    }

    /// Rename `Param1`, `Param2`, … keys in `data` to their declared field names.
    ///
    /// Keys that are not `ParamN` (already named, or from a different format) are
    /// left untouched. If the provider/event combination is unknown, `data` is
    /// returned unchanged.
    pub fn resolve_fields(
        &self,
        event_id: u32,
        provider_guid: &str,
        data: &mut HashMap<String, String>,
    ) {
        let key = (normalize_guid(provider_guid), event_id);
        let Some(fields) = self.templates.get(&key) else {
            return;
        };

        let mut renames: Vec<(String, String)> = Vec::new();
        for (k, _) in data.iter() {
            if let Some(idx) = param_index(k) {
                if idx < fields.len() {
                    renames.push((k.clone(), fields[idx].clone()));
                }
            }
        }
        for (old, new) in renames {
            if let Some(v) = data.remove(&old) {
                data.insert(new, v);
            }
        }
    }
}

impl Default for ManifestDb {
    fn default() -> Self {
        ManifestDb::new()
    }
}

/// Return 0-based index from a `Param1`-style key, or `None` if not that pattern.
fn param_index(key: &str) -> Option<usize> {
    let rest = key.strip_prefix("Param")?;
    rest.parse::<usize>().ok()?.checked_sub(1)
}

/// Normalise a provider GUID to lowercase with surrounding braces.
fn normalize_guid(guid: &str) -> String {
    let s = guid.trim();
    let inner = s.trim_start_matches('{').trim_end_matches('}');
    format!("{{{}}}", inner.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<instrumentationManifest>
  <instrumentation>
    <events>
      <provider name="Test-Provider" guid="{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}">
        <templates>
          <template tid="T_1">
            <data name="TestField" inType="win:UnicodeString"/>
          </template>
        </templates>
        <events>
          <event value="1" template="T_1"/>
        </events>
      </provider>
    </events>
  </instrumentation>
</instrumentationManifest>"#;

    #[test]
    fn resolve_known_event_renames_param_fields() {
        let db = ManifestDb::load_bundled();
        let mut data = HashMap::from([
            ("Param1".to_string(), "S-1-5-21-123".to_string()),
            ("Param2".to_string(), "ADMIN".to_string()),
        ]);
        db.resolve_fields(4624, "{54849625-5478-4994-A5BA-3E3B0328C30D}", &mut data);
        assert!(
            data.contains_key("SubjectUserSid"),
            "Param1 should be renamed to SubjectUserSid"
        );
        assert!(
            data.contains_key("SubjectUserName"),
            "Param2 should be renamed to SubjectUserName"
        );
        assert!(!data.contains_key("Param1"), "Param1 key should be removed");
        assert!(!data.contains_key("Param2"), "Param2 key should be removed");
    }

    #[test]
    fn resolve_unknown_provider_leaves_fields_unchanged() {
        let db = ManifestDb::load_bundled();
        let mut data = HashMap::from([("Param1".to_string(), "value".to_string())]);
        db.resolve_fields(9999, "{00000000-0000-0000-0000-000000000000}", &mut data);
        assert!(
            data.contains_key("Param1"),
            "unknown provider: Param1 must remain unchanged"
        );
        assert_eq!(data["Param1"], "value");
    }

    #[test]
    fn manifest_db_loads_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.man"), MINIMAL_MANIFEST).unwrap();
        let db = ManifestDb::load_from_directory(dir.path()).unwrap();
        let mut data = HashMap::from([("Param1".to_string(), "v".to_string())]);
        db.resolve_fields(1, "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}", &mut data);
        assert!(
            data.contains_key("TestField"),
            "Param1 should be renamed to TestField"
        );
        assert!(!data.contains_key("Param1"), "Param1 key should be removed");
    }

    #[test]
    fn bundled_snapshot_covers_security_channel() {
        let db = ManifestDb::load_bundled();
        let security_guid = "{54849625-5478-4994-A5BA-3E3B0328C30D}";

        // EID 4624 Logon: Param1→SubjectUserSid, Param9→LogonType
        let mut data4624 = HashMap::from([
            ("Param1".to_string(), "S-1-0-0".to_string()),
            ("Param9".to_string(), "3".to_string()),
        ]);
        db.resolve_fields(4624, security_guid, &mut data4624);
        assert!(
            data4624.contains_key("SubjectUserSid"),
            "EID 4624 Param1 must resolve to SubjectUserSid"
        );
        assert!(
            data4624.contains_key("LogonType"),
            "EID 4624 Param9 must resolve to LogonType"
        );

        // EID 4688 Process Create: Param1→SubjectUserSid, Param5→NewProcessId
        let mut data4688 = HashMap::from([
            ("Param1".to_string(), "S-1-0-0".to_string()),
            ("Param5".to_string(), "0x1234".to_string()),
        ]);
        db.resolve_fields(4688, security_guid, &mut data4688);
        assert!(
            data4688.contains_key("SubjectUserSid"),
            "EID 4688 Param1 must resolve to SubjectUserSid"
        );
        assert!(
            data4688.contains_key("NewProcessId"),
            "EID 4688 Param5 must resolve to NewProcessId"
        );
    }
}

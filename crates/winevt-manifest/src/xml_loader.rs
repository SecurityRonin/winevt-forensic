use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::normalize_guid;

/// Parse a Windows provider manifest XML string and insert template definitions
/// into `out`. The manifest format is:
///
/// ```xml
/// <provider guid="{...}">
///   <templates>
///     <template tid="T_foo">
///       <data name="FieldName" .../>
///     </template>
///   </templates>
///   <events>
///     <event value="1234" template="T_foo"/>
///   </events>
/// </provider>
/// ```
pub fn load_into(
    xml: &str,
    out: &mut HashMap<(String, u32), Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    // Pass 1 — collect templates: tid -> Vec<field_name>
    let mut templates: HashMap<String, Vec<String>> = HashMap::new();
    // Pass 2 — collect event-to-template mappings: (guid, event_value) -> tid
    let mut event_map: Vec<(String, u32, String)> = Vec::new();

    let mut current_provider_guid = String::new();
    let mut current_template_tid = String::new();
    let mut in_template = false;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) | Event::Empty(e) => {
                let name = std::str::from_utf8(e.name().as_ref())?.to_lowercase();
                match name.as_str() {
                    "provider" => {
                        current_provider_guid = attr_value(&e, "guid").unwrap_or_default();
                    }
                    "template" => {
                        current_template_tid = attr_value(&e, "tid").unwrap_or_default();
                        in_template = true;
                        templates.entry(current_template_tid.clone()).or_default();
                    }
                    "data" if in_template => {
                        if let Some(field_name) = attr_value(&e, "name") {
                            templates
                                .entry(current_template_tid.clone())
                                .or_default()
                                .push(field_name);
                        }
                    }
                    "event" => {
                        let value = attr_value(&e, "value").unwrap_or_default();
                        let template = attr_value(&e, "template").unwrap_or_default();
                        if let Ok(eid) = value.parse::<u32>() {
                            event_map.push((current_provider_guid.clone(), eid, template));
                        }
                    }
                    _ => {}
                }
            }
            Event::End(e) => {
                let name = std::str::from_utf8(e.name().as_ref())?.to_lowercase();
                if name == "template" {
                    in_template = false;
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    // Merge: for each (guid, eid, tid) we found, look up the template fields
    for (guid, eid, tid) in event_map {
        if let Some(fields) = templates.get(&tid) {
            let key = (normalize_guid(&guid), eid);
            out.entry(key).or_insert_with(|| fields.clone());
        }
    }

    Ok(())
}

fn attr_value(e: &quick_xml::events::BytesStart<'_>, attr_name: &str) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref().eq_ignore_ascii_case(attr_name.as_bytes()) {
            return String::from_utf8(attr.value.into_owned()).ok();
        }
    }
    None
}

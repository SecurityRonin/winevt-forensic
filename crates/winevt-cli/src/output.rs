//! Output-format vocabulary and the human render (Humble Object — pure and
//! directly unit-testable; `main` is the thin shell that owns stdout).
//!
//! The fleet standard splits **human views** (rendered for eyes: clean labels,
//! char-safe truncation) from **machine views** (`json`, `jsonl`, `csv` —
//! exact serialization, never humanized or truncated). This module owns the
//! human side plus the decision of which side to render.

use std::fmt::Write as _;

use serde_json::Value;

/// Widest a single table cell renders before it is elided. Long EVTX fields
/// (command lines, XML blobs) otherwise destroy column alignment.
const MAX_CELL: usize = 48;

/// Output format for `ev4n6 extract`.
///
/// `jsonl` is the fleet-canonical spelling for newline-delimited JSON — the
/// same encoding the pre-existing `--stream` flag emits. `ndjson` is accepted
/// as a hidden alias so anything already written against that spelling keeps
/// working.
#[derive(clap::ValueEnum, Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputFormat {
    /// Aligned, human-readable columns.
    Table,
    /// Pretty-printed JSON array.
    Json,
    /// Newline-delimited JSON — one JSON object per line.
    #[value(name = "jsonl", alias = "ndjson")]
    Jsonl,
    /// Comma-separated values with a header row.
    Csv,
}

/// Resolve the effective format from an optional explicit `--format` and
/// whether stdout is a terminal.
///
/// * An explicit `--format` always wins.
/// * No `--format` on a terminal renders the human [`OutputFormat::Table`].
/// * No `--format` on a pipe keeps [`OutputFormat::Json`] — the behaviour every
///   existing `ev4n6 extract ... | jq` invocation already depends on.
#[must_use]
pub fn resolve(explicit: Option<OutputFormat>, stdout_is_tty: bool) -> OutputFormat {
    match explicit {
        Some(format) => format,
        None if stdout_is_tty => OutputFormat::Table,
        None => OutputFormat::Json,
    }
}

/// Character count, never byte length — so truncation and padding stay correct
/// (and panic-free) on CJK and emoji, which `&s[..n]` would split mid-codepoint.
fn char_width(s: &str) -> usize {
    s.chars().count()
}

/// Truncate to `max` characters on a char boundary, marking the elision.
///
/// Human view only. Machine views never truncate — a JSONL or CSV cell carries
/// the value verbatim.
fn truncate_cell(s: &str, max: usize) -> String {
    if char_width(s) <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Render one JSON scalar as a display cell, unwrapping the serialization
/// quoting so a string reads as its text rather than as `"text"`.
fn cell(v: &Value) -> String {
    let raw = match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    // Strip control characters (including the bidi overrides that can visually
    // reverse a filename) before anything reaches a terminal.
    let clean: String = raw
        .chars()
        .map(|c| {
            if c.is_control()
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
            {
                ' '
            } else {
                c
            }
        })
        .collect();
    truncate_cell(clean.trim(), MAX_CELL)
}

/// Render a slice of JSON objects as an aligned table.
///
/// Column order follows the key order of the first object; keys absent from a
/// later object render as an empty cell. A non-object input, or an empty slice,
/// renders the explicit `(no records)` line rather than nothing at all — an
/// analyst must never be unable to tell "no results" from "the tool broke".
#[must_use]
pub fn render_table(values: &[Value]) -> String {
    let Some(Value::Object(first)) = values.first() else {
        return "(no records)\n".to_string();
    };
    let headers: Vec<String> = first.keys().cloned().collect();
    if headers.is_empty() {
        return "(no records)\n".to_string();
    }

    let rows: Vec<Vec<String>> = values
        .iter()
        .map(|v| {
            headers
                .iter()
                .map(|h| match v {
                    Value::Object(m) => m.get(h).map_or_else(String::new, cell),
                    other => cell(other),
                })
                .collect()
        })
        .collect();

    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .map(|r| r.get(i).map_or(0, |c| char_width(c)))
                .max()
                .unwrap_or(0)
                .max(char_width(h))
        })
        .collect();

    let pad = |s: &str, w: usize| {
        let fill = w.saturating_sub(char_width(s));
        format!("{s}{}", " ".repeat(fill))
    };

    let mut out = String::new();
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| pad(&h.to_uppercase(), widths[i]))
        .collect();
    out.push_str(header_line.join("  ").trim_end());
    out.push('\n');

    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    out.push_str(&sep.join("  "));
    out.push('\n');

    for row in &rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, c)| pad(c, widths[i]))
            .collect();
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
    }

    let _ = write!(out, "\nTotal: {} record(s)\n", rows.len());
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn explicit_format_always_wins_over_tty_state() {
        for tty in [true, false] {
            assert_eq!(
                resolve(Some(OutputFormat::Csv), tty),
                OutputFormat::Csv,
                "an explicit --format must win regardless of stdout being a tty"
            );
        }
    }

    #[test]
    fn no_format_on_a_terminal_renders_the_human_table() {
        assert_eq!(resolve(None, true), OutputFormat::Table);
    }

    #[test]
    fn no_format_on_a_pipe_keeps_json() {
        assert_eq!(
            resolve(None, false),
            OutputFormat::Json,
            "a pipe must keep receiving JSON — existing `| jq` invocations depend on it"
        );
    }

    #[test]
    fn ndjson_is_a_hidden_alias_of_jsonl() {
        use clap::ValueEnum as _;
        let v = OutputFormat::from_str("ndjson", false).expect("legacy ndjson must parse");
        assert_eq!(v, OutputFormat::Jsonl);
        let advertised: Vec<String> = OutputFormat::value_variants()
            .iter()
            .filter_map(clap::ValueEnum::to_possible_value)
            .map(|p| p.get_name().to_string())
            .collect();
        assert!(advertised.iter().any(|n| n == "jsonl"));
        assert!(
            !advertised.iter().any(|n| n == "ndjson"),
            "ndjson is a compatibility alias, not a second advertised name: {advertised:?}"
        );
    }

    #[test]
    fn table_aligns_columns_and_uppercases_headers() {
        let rows = vec![
            json!({"event_id": 4688, "image": "cmd.exe"}),
            json!({"event_id": 4624, "image": "powershell.exe"}),
        ];
        let out = render_table(&rows);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "EVENT_ID  IMAGE");
        assert_eq!(lines[1], "--------  --------------");
        assert_eq!(lines[2], "4688      cmd.exe");
        assert_eq!(lines[3], "4624      powershell.exe");
        assert!(out.contains("Total: 2 record(s)"));
    }

    #[test]
    fn table_unwraps_string_quoting_for_the_human_view() {
        let out = render_table(&[json!({"image": "cmd.exe"})]);
        assert!(
            out.contains("cmd.exe") && !out.contains("\"cmd.exe\""),
            "a human view shows the text, not its JSON quoting: {out}"
        );
    }

    #[test]
    fn table_fills_a_missing_key_with_an_empty_cell() {
        let rows = vec![json!({"a": 1, "b": 2}), json!({"a": 3})];
        let out = render_table(&rows);
        assert!(out.contains("Total: 2 record(s)"), "{out}");
        assert_eq!(out.lines().nth(3).unwrap().trim_end(), "3");
    }

    #[test]
    fn empty_input_says_so_rather_than_rendering_nothing() {
        assert_eq!(render_table(&[]), "(no records)\n");
        assert_eq!(render_table(&[json!("scalar")]), "(no records)\n");
    }

    #[test]
    fn truncation_is_char_safe_on_cjk_and_emoji() {
        // 60 CJK chars — byte-slicing at 47 would split a 3-byte codepoint and panic.
        let wide = "字".repeat(60);
        let out = render_table(&[json!({ "path": wide })]);
        assert!(out.contains('…'), "long cell must be elided: {out}");

        let emoji = "🙂".repeat(60);
        let out = render_table(&[json!({ "path": emoji })]);
        assert!(out.contains('…'));
        // 47 kept + the ellipsis.
        let cell_line = out.lines().nth(2).unwrap();
        assert_eq!(cell_line.chars().count(), MAX_CELL);
    }

    #[test]
    fn control_and_bidi_characters_never_reach_the_terminal() {
        let out = render_table(&[json!({"name": "invoice\u{202e}fdp.exe"})]);
        assert!(
            !out.contains('\u{202e}'),
            "the bidi override must be neutralized: {out:?}"
        );
    }

    #[test]
    fn null_renders_as_an_empty_cell() {
        let out = render_table(&[json!({"a": 1, "b": Value::Null})]);
        assert_eq!(out.lines().nth(2).unwrap().trim_end(), "1");
    }
}

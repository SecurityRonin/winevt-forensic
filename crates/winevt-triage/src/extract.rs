//! EVTX extraction from E01 — stub for RED phase; implemented in GREEN.

use std::path::Path;

use crate::{TriageError, TriageReport};

pub(crate) fn run(_e01_path: &Path, _out_dir: &Path) -> Result<TriageReport, TriageError> {
    unimplemented!("GREEN phase: implement E01 → EVTX extraction")
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TriageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("EWF error: {0}")]
    Ewf(String),

    #[error("no NTFS partition found in MBR")]
    NoNtfsPartition,

    #[error("NTFS error: {0}")]
    Ntfs(String),

    #[error("directory not found in image: {0}")]
    DirNotFound(String),

    #[error("no EVTX files found under Windows/System32/winevt/Logs")]
    NoEvtxFiles,
}

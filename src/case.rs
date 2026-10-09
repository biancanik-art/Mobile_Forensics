use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use crate::models::{ActionRecord, ErrorRecord};

pub struct CasePaths {
    pub root: PathBuf,
    pub native: PathBuf,
    pub logs: PathBuf,
    pub metadata: PathBuf,
    pub actions: PathBuf,
    pub errors: PathBuf,
    pub manifest: PathBuf,
    pub integrity: PathBuf,
}

impl CasePaths {
    pub fn create(base: &Path, case_id: &str, evidence_id: &str) -> Result<Self> {
        let root = base.join(case_id).join(evidence_id);
        let native = root.join("native");
        let logs = root.join("logs");
        let metadata = root.join("metadata");
        fs::create_dir_all(&native)?;
        fs::create_dir_all(&logs)?;
        fs::create_dir_all(&metadata)?;
        Ok(Self {
            actions: root.join("actions.jsonl"),
            errors: root.join("errors.jsonl"),
            manifest: root.join("hashes.sha256"),
            integrity: root.join("integrity.json"),
            root,
            native,
            logs,
            metadata,
        })
    }
}

pub fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

pub fn log_action(
    paths: &CasePaths,
    action: &str,
    command: Option<String>,
    status: &str,
    detail: Option<String>,
) -> Result<()> {
    append_jsonl(
        &paths.actions,
        &ActionRecord {
            timestamp_utc: Utc::now().to_rfc3339(),
            action,
            command,
            status,
            detail,
        },
    )
}

pub fn log_error(paths: &CasePaths, stage: &str, err: &anyhow::Error) {
    let _ = append_jsonl(
        &paths.errors,
        &ErrorRecord {
            timestamp_utc: Utc::now().to_rfc3339(),
            stage,
            error: format!("{err:#}"),
        },
    );
}

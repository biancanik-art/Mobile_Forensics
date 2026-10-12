use std::fs;
use std::path::Path;

use anyhow::Result;
use chrono::Utc;
use walkdir::WalkDir;

use crate::case::{append_jsonl, CasePaths};
use crate::hashing::sha256_file;
use crate::models::ArtifactRecord;

fn relative(paths: &CasePaths, path: &Path) -> String {
    path.strip_prefix(&paths.root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn record_file(
    paths: &CasePaths,
    stage: &str,
    method: &str,
    source: Option<String>,
    destination: &Path,
    status: &str,
    note: Option<String>,
) -> Result<()> {
    let (size, sha256) = if destination.is_file() {
        let size = fs::metadata(destination).ok().map(|m| m.len());
        let sha256 = sha256_file(destination).ok();
        (size, sha256)
    } else {
        (None, None)
    };

    append_jsonl(
        &paths.artifacts,
        &ArtifactRecord {
            timestamp_utc: Utc::now().to_rfc3339(),
            stage: stage.to_string(),
            method: method.to_string(),
            source,
            destination: Some(relative(paths, destination)),
            status: status.to_string(),
            size,
            sha256,
            note,
        },
    )
}

pub fn record_tree(
    paths: &CasePaths,
    stage: &str,
    method: &str,
    source_prefix: &str,
    root: &Path,
) -> Result<usize> {
    if !root.exists() {
        return Ok(0);
    }

    let mut count = 0usize;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        record_file(
            paths,
            stage,
            method,
            Some(format!("{source_prefix}{rel}")),
            path,
            "acquired",
            None,
        )?;
        count += 1;
    }
    Ok(count)
}

pub fn record_failure(
    paths: &CasePaths,
    stage: &str,
    method: &str,
    source: Option<String>,
    destination: Option<&Path>,
    note: String,
) -> Result<()> {
    append_jsonl(
        &paths.artifacts,
        &ArtifactRecord {
            timestamp_utc: Utc::now().to_rfc3339(),
            stage: stage.to_string(),
            method: method.to_string(),
            source,
            destination: destination.map(|p| relative(paths, p)),
            status: "failed".to_string(),
            size: None,
            sha256: None,
            note: Some(note),
        },
    )
}

use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{anyhow, Context, Result};

pub fn executable_name(name: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        if name.to_ascii_lowercase().ends_with(".exe") {
            name.to_string()
        } else {
            format!("{name}.exe")
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        name.to_string()
    }
}

pub fn find_executable(name: &str, preferred_dir: Option<&Path>) -> Option<PathBuf> {
    let exe = executable_name(name);

    if let Some(dir) = preferred_dir {
        let p = dir.join(&exe);
        if p.is_file() {
            return Some(p);
        }
    }

    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join(&exe);
            if p.is_file() {
                return Some(p);
            }
        }
    }

    None
}

pub fn run_capture<I, S>(program: &Path, args: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {}", program.display()))
}

pub fn run_checked<I, S>(program: &Path, args: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let out = run_capture(program, args)?;
    if !out.status.success() {
        return Err(anyhow!(
            "{} failed with status {:?}: {}",
            program.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out)
}

pub fn run_to_logs(
    program: &Path,
    args: &[String],
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<std::process::ExitStatus> {
    let stdout = File::create(stdout_path)?;
    let stderr = File::create(stderr_path)?;
    Command::new(program)
        .args(args)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .with_context(|| format!("failed to execute {}", program.display()))
}

pub fn text_stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn format_command(program: &Path, args: &[String]) -> String {
    let mut out = program.display().to_string();
    for arg in args {
        out.push(' ');
        if arg.contains(' ') || arg.contains('\t') {
            out.push('"');
            out.push_str(&arg.replace('"', "\\\""));
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    out
}

pub fn version_of(program: &Path) -> Option<String> {
    for flag in ["--version", "-v"] {
        if let Ok(out) = run_capture(program, [flag]) {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let value = if !stdout.is_empty() { stdout } else { stderr };
                if !value.is_empty() {
                    return Some(value.lines().next().unwrap_or(&value).to_string());
                }
            }
        }
    }
    None
}

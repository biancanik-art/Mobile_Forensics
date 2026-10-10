use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;

use crate::android::{adb_path, inspect_android, select_android_device};
use crate::case::{log_action, log_error, write_json, CasePaths};
use crate::command::{format_command, run_capture, run_to_logs};
use crate::hashing::{hash_tree, sha256_file};
use crate::ios::{inspect_ios, pairing_valid, select_ios_device};
use crate::models::{AcquisitionSummary, IntegrityRecord, Platform, Profile};
use crate::tooling::{safe_ios_tools, ToolResolver};

fn capture_to_file(
    paths: &CasePaths,
    stage: &str,
    program: &Path,
    args: &[String],
    destination: &Path,
) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let display = format_command(program, args);
    log_action(paths, stage, Some(display.clone()), "started", None)?;
    match run_capture(program, args.iter().map(String::as_str)) {
        Ok(output) => {
            let mut file = File::create(destination)?;
            file.write_all(&output.stdout)?;
            if !output.stderr.is_empty() {
                file.write_all(b"\n--- STDERR ---\n")?;
                file.write_all(&output.stderr)?;
            }
            if output.status.success() {
                log_action(
                    paths,
                    stage,
                    Some(display),
                    "completed",
                    Some(format!("wrote {}", destination.display())),
                )?;
                Ok(())
            } else {
                let err = anyhow!("{} exited with {:?}", program.display(), output.status.code());
                log_error(paths, stage, &err);
                log_action(
                    paths,
                    stage,
                    Some(display),
                    "failed",
                    Some(format!("{err:#}")),
                )?;
                Err(err)
            }
        }
        Err(err) => {
            log_error(paths, stage, &err);
            log_action(
                paths,
                stage,
                Some(display),
                "failed",
                Some(format!("{err:#}")),
            )?;
            Err(err)
        }
    }
}

fn run_logged(paths: &CasePaths, stage: &str, program: &Path, args: &[String]) -> Result<()> {
    let stdout_path = paths.logs.join(format!("{stage}.stdout.log"));
    let stderr_path = paths.logs.join(format!("{stage}.stderr.log"));
    let display = format_command(program, args);
    log_action(paths, stage, Some(display.clone()), "started", None)?;
    let status = run_to_logs(program, args, &stdout_path, &stderr_path)?;
    if status.success() {
        log_action(paths, stage, Some(display), "completed", None)?;
        Ok(())
    } else {
        let err = anyhow!("{} failed with status {:?}", program.display(), status.code());
        log_error(paths, stage, &err);
        log_action(
            paths,
            stage,
            Some(display),
            "failed",
            Some(format!("{err:#}")),
        )?;
        Err(err)
    }
}

fn write_tool_inventory(
    paths: &CasePaths,
    resolver: &ToolResolver,
    platform: Platform,
) -> Result<()> {
    let tools = match platform {
        Platform::Android => vec![resolver.describe_adb()],
        Platform::Ios => safe_ios_tools()
            .iter()
            .map(|name| resolver.describe_ios(name))
            .collect(),
    };
    write_json(&paths.metadata.join("tools.json"), &tools)
}

#[allow(clippy::too_many_arguments)]
fn finalize(
    paths: &CasePaths,
    started: chrono::DateTime<Utc>,
    case_id: &str,
    evidence_id: &str,
    examiner: &str,
    platform: Platform,
    profile: Profile,
    device_identifier: String,
    warnings: Vec<String>,
) -> Result<()> {
    let summary_path = paths.root.join("acquisition.json");

    // Hash acquired content and operational logs. Summary/integrity files are excluded
    // to avoid a circular digest relationship: both describe the manifest itself.
    let exclusions = [summary_path.as_path(), paths.integrity.as_path()];
    let files_hashed = hash_tree(&paths.root, &paths.manifest, &exclusions)?;
    let manifest_sha256 = sha256_file(&paths.manifest)?;

    let final_summary = AcquisitionSummary {
        tool: "Mobile Acquire".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        case_id: case_id.into(),
        evidence_id: evidence_id.into(),
        examiner: examiner.into(),
        platform,
        profile,
        device_identifier,
        started_utc: started.to_rfc3339(),
        ended_utc: Utc::now().to_rfc3339(),
        status: if warnings.is_empty() {
            "completed".into()
        } else {
            "completed_with_warnings".into()
        },
        output_directory: paths.root.display().to_string(),
        files_hashed,
        manifest_sha256: Some(manifest_sha256.clone()),
        warnings,
    };
    write_json(&summary_path, &final_summary)?;

    let integrity = IntegrityRecord {
        algorithm: "SHA-256".into(),
        manifest: "hashes.sha256".into(),
        manifest_sha256: manifest_sha256.clone(),
        files_hashed,
        generated_utc: Utc::now().to_rfc3339(),
    };
    write_json(&paths.integrity, &integrity)?;

    println!("Acquisition complete: {}", paths.root.display());
    println!("Files hashed: {files_hashed}");
    println!("Manifest SHA-256: {manifest_sha256}");
    Ok(())
}

pub fn acquire_android(
    resolver: &ToolResolver,
    requested: Option<&str>,
    profile: Profile,
    case_id: &str,
    evidence_id: &str,
    examiner: &str,
    base: &Path,
) -> Result<()> {
    let serial = select_android_device(resolver, requested)?;
    let probe = inspect_android(resolver, &serial)?;
    if probe.device.pairing_or_adb_authorized != Some(true) {
        bail!("ADB is not authorized; acquisition will not attempt to change device trust/state");
    }

    let adb = adb_path(resolver)?;
    let paths = CasePaths::create(base, case_id, evidence_id)?;
    let started = Utc::now();
    write_json(&paths.metadata.join("device.json"), &probe.device)?;
    write_json(
        &paths.metadata.join("capabilities.json"),
        &probe.capabilities,
    )?;
    write_tool_inventory(&paths, resolver, Platform::Android)?;
    log_action(
        &paths,
        "acquisition",
        None,
        "started",
        Some(format!("android serial={serial} profile={profile:?}")),
    )?;

    let android = paths.native.join("android");
    fs::create_dir_all(&android)?;
    let mut warnings = Vec::new();
    let adb_args = |tail: &[&str]| -> Vec<String> {
        let mut args = vec!["-s".into(), serial.clone()];
        args.extend(tail.iter().map(|s| (*s).to_string()));
        args
    };

    let collectors = [
        ("getprop", vec!["shell", "getprop"], "getprop.txt"),
        (
            "packages",
            vec!["shell", "pm", "list", "packages", "-f"],
            "packages.txt",
        ),
        ("mounts", vec!["shell", "mount"], "mounts.txt"),
        ("df", vec!["shell", "df", "-h"], "df.txt"),
        (
            "users",
            vec!["shell", "dumpsys", "user"],
            "dumpsys_user.txt",
        ),
        (
            "settings_global",
            vec!["shell", "settings", "list", "global"],
            "settings_global.txt",
        ),
        (
            "settings_secure",
            vec!["shell", "settings", "list", "secure"],
            "settings_secure.txt",
        ),
        ("dumpsys", vec!["shell", "dumpsys"], "dumpsys.txt"),
        (
            "logcat",
            vec!["logcat", "-d", "-v", "threadtime"],
            "logcat.txt",
        ),
    ];

    for (stage, tail, filename) in collectors {
        let args = adb_args(&tail);
        if let Err(err) =
            capture_to_file(&paths, stage, &adb, &args, &android.join(filename))
        {
            warnings.push(format!("{stage}: {err:#}"));
        }
    }

    let bugreport = android.join("bugreport.zip");
    let bugreport_s = bugreport.to_string_lossy().to_string();
    let args = adb_args(&["bugreport", bugreport_s.as_str()]);
    if let Err(err) = run_logged(&paths, "bugreport", &adb, &args) {
        warnings.push(format!("bugreport: {err:#}"));
    }

    if matches!(profile, Profile::Logical | Profile::Enhanced) {
        let shared = android.join("shared-storage");
        fs::create_dir_all(&shared)?;
        let shared_s = shared.to_string_lossy().to_string();
        let args = adb_args(&["pull", "/sdcard/", shared_s.as_str()]);
        if let Err(err) = run_logged(&paths, "shared_storage_pull", &adb, &args) {
            warnings.push(format!("shared storage pull: {err:#}"));
        }
    }

    if matches!(profile, Profile::Enhanced)
        && probe.device.root_or_jailbreak_detected == Some(true)
    {
        warnings.push("Existing root was detected, but raw/root filesystem streaming is intentionally not enabled in v0.2.0 yet; no privilege-changing action was performed.".into());
    }

    log_action(
        &paths,
        "acquisition",
        None,
        "collection_complete",
        None,
    )?;
    finalize(
        &paths,
        started,
        case_id,
        evidence_id,
        examiner,
        Platform::Android,
        profile,
        serial,
        warnings,
    )
}

pub fn acquire_ios(
    resolver: &ToolResolver,
    requested: Option<&str>,
    profile: Profile,
    case_id: &str,
    evidence_id: &str,
    examiner: &str,
    base: &Path,
) -> Result<()> {
    let udid = select_ios_device(resolver, requested)?;
    let probe = inspect_ios(resolver, &udid)?;
    let paths = CasePaths::create(base, case_id, evidence_id)?;
    let started = Utc::now();
    write_json(&paths.metadata.join("device.json"), &probe.device)?;
    write_json(
        &paths.metadata.join("capabilities.json"),
        &probe.capabilities,
    )?;
    write_tool_inventory(&paths, resolver, Platform::Ios)?;
    log_action(
        &paths,
        "acquisition",
        None,
        "started",
        Some(format!("ios udid={udid} profile={profile:?}")),
    )?;

    let ios = paths.native.join("ios");
    fs::create_dir_all(&ios)?;
    let mut warnings = Vec::new();

    let info = resolver
        .ios("ideviceinfo")
        .context("ideviceinfo unavailable")?;
    let simple_args = vec!["-s".into(), "-u".into(), udid.clone()];
    if let Err(err) = capture_to_file(
        &paths,
        "ideviceinfo_simple",
        &info,
        &simple_args,
        &ios.join("ideviceinfo-simple.txt"),
    ) {
        warnings.push(format!("ideviceinfo --simple: {err:#}"));
    }

    let paired = pairing_valid(resolver, &udid) == Some(true);
    if let Some(pair) = resolver.ios("idevicepair") {
        let args = vec!["-u".into(), udid.clone(), "validate".into()];
        if let Err(err) = capture_to_file(
            &paths,
            "pairing_validate",
            &pair,
            &args,
            &ios.join("pairing-validate.txt"),
        ) {
            warnings.push(format!("pairing validate: {err:#}"));
        }
    }

    if paired {
        let args = vec!["-u".into(), udid.clone()];
        if let Err(err) = capture_to_file(
            &paths,
            "ideviceinfo_full",
            &info,
            &args,
            &ios.join("ideviceinfo-full.txt"),
        ) {
            warnings.push(format!("ideviceinfo full: {err:#}"));
        }
    } else if matches!(profile, Profile::Logical | Profile::Enhanced) {
        warnings.push("No existing valid pairing. MobileBackup2/AFC-style logical acquisition was not attempted and the tool did not create a new pairing.".into());
    }

    if paired
        && matches!(
            profile,
            Profile::Quick | Profile::Logical | Profile::Enhanced
        )
    {
        if let Some(crash) = resolver.ios("idevicecrashreport") {
            let crash_dir = ios.join("crash-reports");
            fs::create_dir_all(&crash_dir)?;
            let args = vec![
                "-u".into(),
                udid.clone(),
                "-k".into(),
                crash_dir.to_string_lossy().to_string(),
            ];
            if let Err(err) =
                run_logged(&paths, "crash_reports_copy", &crash, &args)
            {
                warnings.push(format!("crash reports: {err:#}"));
            }
        }
    }

    if paired && matches!(profile, Profile::Logical | Profile::Enhanced) {
        let backup = resolver
            .ios("idevicebackup2")
            .context("idevicebackup2 unavailable")?;
        let backup_dir = ios.join("mobilebackup2");
        fs::create_dir_all(&backup_dir)?;
        let args = vec![
            "-u".into(),
            udid.clone(),
            "backup".into(),
            "--full".into(),
            backup_dir.to_string_lossy().to_string(),
        ];
        if let Err(err) =
            run_logged(&paths, "mobilebackup2_full", &backup, &args)
        {
            warnings.push(format!("MobileBackup2 full backup: {err:#}"));
        }
    }

    if paired && matches!(profile, Profile::Enhanced) {
        if let Some(syslog) = resolver.ios("idevicesyslog") {
            let archive = ios.join("unified-logs.tar");
            let args = vec![
                "-u".into(),
                udid.clone(),
                "archive".into(),
                archive.to_string_lossy().to_string(),
            ];
            if let Err(err) =
                run_logged(&paths, "unified_log_archive", &syslog, &args)
            {
                warnings.push(format!("unified log archive: {err:#}"));
            }
        }

        if let Some(provision) = resolver.ios("ideviceprovision") {
            let provision_dir = ios.join("provisioning-profiles");
            fs::create_dir_all(&provision_dir)?;
            let list_args = vec!["-u".into(), udid.clone(), "list".into()];
            if let Err(err) = capture_to_file(
                &paths,
                "provisioning_list",
                &provision,
                &list_args,
                &ios.join("provisioning-list.txt"),
            ) {
                warnings.push(format!("provisioning list: {err:#}"));
            }
            let copy_args = vec![
                "-u".into(),
                udid.clone(),
                "copy".into(),
                provision_dir.to_string_lossy().to_string(),
            ];
            if let Err(err) =
                run_logged(&paths, "provisioning_copy", &provision, &copy_args)
            {
                warnings.push(format!("provisioning copy: {err:#}"));
            }
        }

        if resolver.ios("afcclient").is_some() {
            warnings.push("AFC service/tool is available, but recursive AFC export is not enabled in v0.2.0 until its non-interactive transport is validated on real devices. No write-capable AFC command is used.".into());
        }
    }

    log_action(
        &paths,
        "acquisition",
        None,
        "collection_complete",
        None,
    )?;
    finalize(
        &paths,
        started,
        case_id,
        evidence_id,
        examiner,
        Platform::Ios,
        profile,
        udid,
        warnings,
    )
}

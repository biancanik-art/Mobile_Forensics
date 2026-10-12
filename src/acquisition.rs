use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;

use crate::android::{adb_path, inspect_android, select_android_device};
use crate::artifacts::{record_failure, record_file, record_status, record_tree};
use crate::case::{log_action, log_error, write_json, CasePaths};
use crate::command::{format_command, run_capture, run_to_logs};
use crate::hashing::{hash_tree, sha256_file};
use crate::ios::{inspect_ios, pairing_valid, select_ios_device};
use crate::models::{AcquisitionSummary, IntegrityRecord, Platform, Profile};
use crate::tooling::{safe_ios_tools, ToolResolver};

fn method_name(program: &Path) -> String {
    program
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("external_tool")
        .to_string()
}

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
    let method = method_name(program);
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
                record_file(
                    paths,
                    stage,
                    &method,
                    Some(format!("command://{stage}")),
                    destination,
                    "acquired",
                    None,
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
                record_failure(
                    paths,
                    stage,
                    &method,
                    Some(format!("command://{stage}")),
                    Some(destination),
                    format!("{err:#}"),
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
            record_failure(
                paths,
                stage,
                &method,
                Some(format!("command://{stage}")),
                Some(destination),
                format!("{err:#}"),
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
        Platform::Ios => {
            let mut tools: Vec<_> = safe_ios_tools()
                .iter()
                .map(|name| resolver.describe_ios(name))
                .collect();
            tools.push(resolver.describe_pymobiledevice3());
            tools
        }
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

    // Standardized raw collection: each surface is preserved separately even when
    // some of the same information also exists inside bugreport/full dumpsys.
    // These probes are read-only and intentionally avoid commands that toggle radios,
    // change settings, reboot the phone, or otherwise modify device state.
    let collectors = [
        ("getprop", vec!["shell", "getprop"], "getprop.txt"),
        (
            "packages",
            vec!["shell", "pm", "list", "packages", "-f", "-U"],
            "packages.txt",
        ),
        (
            "packages_third_party",
            vec!["shell", "pm", "list", "packages", "-3", "-f", "-U"],
            "packages-third-party.txt",
        ),
        ("services", vec!["shell", "dumpsys", "-l"], "dumpsys-services.txt"),
        ("mounts", vec!["shell", "mount"], "mounts.txt"),
        (
            "proc_mounts",
            vec!["shell", "cat", "/proc/mounts"],
            "proc-mounts.txt",
        ),
        ("df", vec!["shell", "df", "-h"], "df.txt"),
        ("users", vec!["shell", "dumpsys", "user"], "dumpsys-user.txt"),
        ("accounts", vec!["shell", "dumpsys", "account"], "dumpsys-account.txt"),
        ("battery", vec!["shell", "dumpsys", "battery"], "dumpsys-battery.txt"),
        (
            "batterystats",
            vec!["shell", "dumpsys", "batterystats"],
            "dumpsys-batterystats.txt",
        ),
        ("power", vec!["shell", "dumpsys", "power"], "dumpsys-power.txt"),
        ("location", vec!["shell", "dumpsys", "location"], "dumpsys-location.txt"),
        ("telecom", vec!["shell", "dumpsys", "telecom"], "dumpsys-telecom.txt"),
        ("usb", vec!["shell", "dumpsys", "usb"], "dumpsys-usb.txt"),
        ("dropbox", vec!["shell", "dumpsys", "dropbox"], "dumpsys-dropbox.txt"),
        ("meminfo", vec!["shell", "dumpsys", "meminfo"], "dumpsys-meminfo.txt"),
        (
            "sensorservice",
            vec!["shell", "dumpsys", "sensorservice"],
            "dumpsys-sensorservice.txt",
        ),
        (
            "audio_flinger",
            vec!["shell", "dumpsys", "media.audio_flinger"],
            "dumpsys-media-audio-flinger.txt",
        ),
        ("adb_state", vec!["shell", "dumpsys", "adb"], "dumpsys-adb.txt"),
        (
            "fingerprint",
            vec!["shell", "dumpsys", "fingerprint"],
            "dumpsys-fingerprint.txt",
        ),
        (
            "lock_settings",
            vec!["shell", "dumpsys", "lock_settings"],
            "dumpsys-lock-settings.txt",
        ),
        ("package", vec!["shell", "dumpsys", "package"], "dumpsys-package.txt"),
        ("window", vec!["shell", "dumpsys", "window"], "dumpsys-window.txt"),
        ("stats", vec!["shell", "dumpsys", "stats"], "dumpsys-stats.txt"),
        (
            "settings_system",
            vec!["shell", "settings", "list", "system"],
            "settings-system.txt",
        ),
        (
            "settings_global",
            vec!["shell", "settings", "list", "global"],
            "settings-global.txt",
        ),
        (
            "settings_secure",
            vec!["shell", "settings", "list", "secure"],
            "settings-secure.txt",
        ),
        (
            "activity_recents",
            vec!["shell", "dumpsys", "activity", "recents"],
            "dumpsys-activity-recents.txt",
        ),
        (
            "usage_stats",
            vec!["shell", "dumpsys", "usagestats"],
            "dumpsys-usagestats.txt",
        ),
        (
            "notification",
            vec!["shell", "dumpsys", "notification"],
            "dumpsys-notification.txt",
        ),
        (
            "connectivity",
            vec!["shell", "dumpsys", "connectivity"],
            "dumpsys-connectivity.txt",
        ),
        (
            "netstats",
            vec!["shell", "dumpsys", "netstats"],
            "dumpsys-netstats.txt",
        ),
        ("wifi", vec!["shell", "dumpsys", "wifi"], "dumpsys-wifi.txt"),
        (
            "device_policy",
            vec!["shell", "dumpsys", "device_policy"],
            "dumpsys-device-policy.txt",
        ),
        ("ip_addr", vec!["shell", "ip", "addr"], "ip-addr.txt"),
        ("ip_route", vec!["shell", "ip", "route"], "ip-route.txt"),
        ("dumpsys", vec!["shell", "dumpsys"], "dumpsys.txt"),
        (
            "logcat",
            vec!["logcat", "-d", "-v", "threadtime"],
            "logcat.txt",
        ),
    ];

    for (stage, tail, filename) in collectors {
        let args = adb_args(&tail);
        if let Err(err) = capture_to_file(&paths, stage, &adb, &args, &android.join(filename)) {
            warnings.push(format!("{stage}: {err:#}"));
        }
    }

    let bugreport = android.join("bugreport.zip");
    let bugreport_s = bugreport.to_string_lossy().to_string();
    let args = adb_args(&["bugreport", bugreport_s.as_str()]);
    match run_logged(&paths, "bugreport", &adb, &args) {
        Ok(()) => {
            if bugreport.is_file() {
                record_file(
                    &paths,
                    "bugreport",
                    "adb",
                    Some("android://bugreport".into()),
                    &bugreport,
                    "acquired",
                    None,
                )?;
            } else {
                record_status(
                    &paths,
                    "bugreport",
                    "adb",
                    Some("android://bugreport".into()),
                    Some(&bugreport),
                    "completed_no_expected_file",
                    Some("adb reported success but the expected ZIP path was not present".into()),
                )?;
            }
        }
        Err(err) => {
            record_failure(
                &paths,
                "bugreport",
                "adb",
                Some("android://bugreport".into()),
                Some(&bugreport),
                format!("{err:#}"),
            )?;
            warnings.push(format!("bugreport: {err:#}"));
        }
    }

    if matches!(profile, Profile::Logical | Profile::Enhanced) {
        let shared = android.join("shared-storage");
        fs::create_dir_all(&shared)?;
        let shared_s = shared.to_string_lossy().to_string();
        let args = adb_args(&["pull", "/sdcard/", shared_s.as_str()]);
        match run_logged(&paths, "shared_storage_pull", &adb, &args) {
            Ok(()) => {
                let count = record_tree(
                    &paths,
                    "shared_storage_pull",
                    "adb pull",
                    "/sdcard/",
                    &shared,
                )?;
                log_action(
                    &paths,
                    "shared_storage_manifest",
                    None,
                    "completed",
                    Some(format!("recorded {count} acquired files")),
                )?;
            }
            Err(err) => {
                record_failure(
                    &paths,
                    "shared_storage_pull",
                    "adb pull",
                    Some("/sdcard/".into()),
                    Some(&shared),
                    format!("{err:#}"),
                )?;
                warnings.push(format!("shared storage pull: {err:#}"));
            }
        }
    }

    if matches!(profile, Profile::Enhanced)
        && probe.device.root_or_jailbreak_detected == Some(true)
    {
        warnings.push("Existing root was detected, but raw/root filesystem streaming is intentionally not enabled in v0.3.0 yet; no privilege-changing action was performed.".into());
        record_status(
            &paths,
            "root_filesystem",
            "adb",
            Some("android://root-filesystem".into()),
            None,
            "not_implemented",
            Some("Existing root detected; raw/root filesystem streaming is reserved for the dedicated acquisition plugin.".into()),
        )?;
    }

    log_action(&paths, "acquisition", None, "collection_complete", None)?;
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
        let note = "No existing valid pairing. MobileBackup2/AFC-style logical acquisition was not attempted and the tool did not create a new pairing.";
        warnings.push(note.into());
        record_status(
            &paths,
            "mobilebackup2_full",
            "libimobiledevice",
            Some("ios://mobilebackup2".into()),
            None,
            "not_attempted",
            Some(note.into()),
        )?;
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
            match run_logged(&paths, "crash_reports_copy", &crash, &args) {
                Ok(()) => {
                    record_tree(
                        &paths,
                        "crash_reports_copy",
                        "idevicecrashreport -k",
                        "ios://crash-reports/",
                        &crash_dir,
                    )?;
                }
                Err(err) => {
                    record_failure(
                        &paths,
                        "crash_reports_copy",
                        "idevicecrashreport -k",
                        Some("ios://crash-reports/".into()),
                        Some(&crash_dir),
                        format!("{err:#}"),
                    )?;
                    warnings.push(format!("crash reports: {err:#}"));
                }
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

        match run_logged(&paths, "mobilebackup2_full", &backup, &args) {
            Ok(()) => {
                let count = record_tree(
                    &paths,
                    "mobilebackup2_full",
                    "idevicebackup2",
                    "ios://mobilebackup2/",
                    &backup_dir,
                )?;
                log_action(
                    &paths,
                    "mobilebackup2_manifest",
                    None,
                    "completed",
                    Some(format!("recorded {count} native backup files")),
                )?;
            }
            Err(err) => {
                record_failure(
                    &paths,
                    "mobilebackup2_full",
                    "idevicebackup2",
                    Some("ios://mobilebackup2/".into()),
                    Some(&backup_dir),
                    format!("{err:#}"),
                )?;
                warnings.push(format!("MobileBackup2 full backup: {err:#}"));
            }
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

            match run_logged(&paths, "unified_log_archive", &syslog, &args) {
                Ok(()) if archive.is_file() => {
                    record_file(
                        &paths,
                        "unified_log_archive",
                        "idevicesyslog archive",
                        Some("ios://unified-logs".into()),
                        &archive,
                        "acquired",
                        None,
                    )?;
                }
                Ok(()) => {
                    record_status(
                        &paths,
                        "unified_log_archive",
                        "idevicesyslog archive",
                        Some("ios://unified-logs".into()),
                        Some(&archive),
                        "completed_no_expected_file",
                        Some("tool returned success but expected archive path is absent".into()),
                    )?;
                }
                Err(err) => {
                    record_failure(
                        &paths,
                        "unified_log_archive",
                        "idevicesyslog archive",
                        Some("ios://unified-logs".into()),
                        Some(&archive),
                        format!("{err:#}"),
                    )?;
                    warnings.push(format!("unified log archive: {err:#}"));
                }
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
            match run_logged(&paths, "provisioning_copy", &provision, &copy_args) {
                Ok(()) => {
                    record_tree(
                        &paths,
                        "provisioning_copy",
                        "ideviceprovision copy",
                        "ios://provisioning-profiles/",
                        &provision_dir,
                    )?;
                }
                Err(err) => {
                    record_failure(
                        &paths,
                        "provisioning_copy",
                        "ideviceprovision copy",
                        Some("ios://provisioning-profiles/".into()),
                        Some(&provision_dir),
                        format!("{err:#}"),
                    )?;
                    warnings.push(format!("provisioning copy: {err:#}"));
                }
            }
        }

        if resolver.ios("afcclient").is_some() {
            let note = "AFC backend is detected, but recursive AFC/HouseArrest export is not automatically enabled until the exact read-only command transport is validated on real devices.";
            warnings.push(note.into());
            record_status(
                &paths,
                "afc_recursive_export",
                "afcclient",
                Some("ios://afc".into()),
                None,
                "not_implemented",
                Some(note.into()),
            )?;
        }
    }

    log_action(&paths, "acquisition", None, "collection_complete", None)?;
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

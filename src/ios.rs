use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};

use crate::command::{run_capture, run_checked};
use crate::models::{Capability, DeviceInfo, Platform, ProbeResult};
use crate::tooling::ToolResolver;

fn required(resolver: &ToolResolver, name: &str) -> Result<PathBuf> {
    resolver
        .ios(name)
        .ok_or_else(|| anyhow!("{name} not found. Put current libimobiledevice tools in PATH, set MOBILE_ACQUIRE_IOS_TOOLS, or pass --ios-tools-dir."))
}

pub fn list_ios_devices(resolver: &ToolResolver) -> Result<Vec<String>> {
    let tool = required(resolver, "idevice_id")?;
    let out = run_checked(&tool, ["-l"])?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

pub fn select_ios_device(resolver: &ToolResolver, requested: Option<&str>) -> Result<String> {
    let devices = list_ios_devices(resolver)?;
    if let Some(udid) = requested {
        if devices.iter().any(|d| d == udid) {
            return Ok(udid.to_string());
        }
        bail!("iOS device {udid} not found");
    }

    match devices.len() {
        0 => bail!("No USB iOS device detected through libimobiledevice/usbmux"),
        1 => Ok(devices[0].clone()),
        _ => bail!("Multiple iOS devices are connected; pass --device <UDID>"),
    }
}

fn parse_ideviceinfo(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

pub fn pairing_valid(resolver: &ToolResolver, udid: &str) -> Option<bool> {
    let tool = resolver.ios("idevicepair")?;
    run_capture(&tool, ["-u", udid, "validate"])
        .map(|o| o.status.success())
        .ok()
}

pub fn inspect_ios(resolver: &ToolResolver, udid: &str) -> Result<ProbeResult> {
    let info_tool = required(resolver, "ideviceinfo")?;

    // -s uses a simple connection and avoids auto-pairing. This is intentional for forensic probing.
    let simple = run_capture(&info_tool, ["-s", "-u", udid])?;
    let simple_text = String::from_utf8_lossy(&simple.stdout).to_string();
    let mut map = parse_ideviceinfo(&simple_text);

    let pairing = pairing_valid(resolver, udid);
    if pairing == Some(true) {
        if let Ok(full) = run_capture(&info_tool, ["-u", udid]) {
            if full.status.success() {
                map.extend(parse_ideviceinfo(&String::from_utf8_lossy(&full.stdout)));
            }
        }
    }

    let mut notes = Vec::new();
    notes.push("Probe uses ideviceinfo --simple first to avoid auto-pairing.".into());
    match pairing {
        Some(true) => notes.push("Existing host pairing validates; no new pairing was created by the tool.".into()),
        Some(false) => notes.push("Existing pairing did not validate. The tool will not issue idevicepair pair automatically.".into()),
        None => notes.push("idevicepair is unavailable, so pairing state could not be validated.".into()),
    }
    notes.push("AFU/BFU is not inferred from lockdownd availability alone.".into());

    let access_state = match pairing {
        Some(true) => "usb_visible_existing_pairing_valid".to_string(),
        Some(false) => "usb_visible_pairing_invalid_or_locked".to_string(),
        None => "usb_visible_pairing_unknown".to_string(),
    };

    let device = DeviceInfo {
        platform: Platform::Ios,
        identifier: udid.to_string(),
        manufacturer: Some("Apple".into()),
        model: map.get("ProductType").cloned(),
        device_name: map.get("DeviceName").cloned(),
        os_version: map.get("ProductVersion").cloned(),
        build: map.get("BuildVersion").cloned(),
        serial_number: map.get("SerialNumber").cloned(),
        pairing_or_adb_authorized: pairing,
        ce_unlocked_since_boot: None,
        root_or_jailbreak_detected: None,
        bootloader_locked: None,
        access_state,
        notes,
    };

    let paired = pairing == Some(true);
    let caps = vec![
        Capability {
            name: "quick_metadata".into(),
            available: simple.status.success(),
            reason: if simple.status.success() { "ideviceinfo --simple succeeded" } else { "simple lockdownd query failed" }.into(),
        },
        Capability {
            name: "native_mobilebackup2".into(),
            available: paired && resolver.ios("idevicebackup2").is_some(),
            reason: if !paired { "Requires existing valid pairing/service access" } else if resolver.ios("idevicebackup2").is_none() { "idevicebackup2 unavailable" } else { "Existing pairing validates and idevicebackup2 is available" }.into(),
        },
        Capability {
            name: "crash_reports_copy".into(),
            available: paired && resolver.ios("idevicecrashreport").is_some(),
            reason: "Uses idevicecrashreport -k so source crash reports are kept on device".into(),
        },
        Capability {
            name: "unified_log_archive".into(),
            available: paired && resolver.ios("idevicesyslog").is_some(),
            reason: "Uses idevicesyslog archive when supported by the device/service".into(),
        },
        Capability {
            name: "provisioning_profiles_copy".into(),
            available: paired && resolver.ios("ideviceprovision").is_some(),
            reason: "Read-only copy operation only; install/remove commands are never used".into(),
        },
        Capability {
            name: "afc_available".into(),
            available: paired && resolver.ios("afcclient").is_some(),
            reason: "AFC backend detected; recursive acquisition is staged for a later tested transport implementation".into(),
        },
    ];

    Ok(ProbeResult { device, capabilities: caps })
}

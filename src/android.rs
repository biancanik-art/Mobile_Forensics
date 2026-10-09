use anyhow::{anyhow, bail, Result};

use crate::command::{run_checked, text_stdout};
use crate::models::{Capability, DeviceInfo, Platform, ProbeResult};
use crate::tooling::ToolResolver;

pub fn list_android_devices(resolver: &ToolResolver) -> Result<Vec<(String, String)>> {
    let adb = resolver
        .adb()
        .ok_or_else(|| anyhow!("adb not found. Install Android Platform Tools or pass --adb <path>."))?;
    let out = run_checked(&adb, ["devices", "-l"])?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut devices = Vec::new();
    for line in text.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(serial) = parts.next() else { continue };
        let state = parts.next().unwrap_or("unknown");
        devices.push((serial.to_string(), state.to_string()));
    }
    Ok(devices)
}

pub fn select_android_device(resolver: &ToolResolver, requested: Option<&str>) -> Result<String> {
    let devices = list_android_devices(resolver)?;
    if let Some(serial) = requested {
        if devices.iter().any(|(s, _)| s == serial) {
            return Ok(serial.to_string());
        }
        bail!("Android device {serial} not found");
    }

    let authorized: Vec<_> = devices.iter().filter(|(_, state)| state == "device").collect();
    match authorized.len() {
        0 => {
            if devices.iter().any(|(_, state)| state == "unauthorized") {
                bail!("Android device is present but ADB is unauthorized. Acquisition will not change the trust state.");
            }
            bail!("No authorized Android device found")
        }
        1 => Ok(authorized[0].0.clone()),
        _ => bail!("Multiple Android devices are connected; pass --device <serial>"),
    }
}

fn adb_shell(resolver: &ToolResolver, serial: &str, args: &[&str]) -> Option<String> {
    let adb = resolver.adb()?;
    let mut all = vec!["-s", serial, "shell"];
    all.extend_from_slice(args);
    let out = run_checked(&adb, all).ok()?;
    Some(text_stdout(&out))
}

fn getprop(resolver: &ToolResolver, serial: &str, key: &str) -> Option<String> {
    adb_shell(resolver, serial, &["getprop", key]).filter(|v| !v.is_empty())
}

pub fn inspect_android(resolver: &ToolResolver, serial: &str) -> Result<ProbeResult> {
    let devices = list_android_devices(resolver)?;
    let state = devices
        .iter()
        .find(|(s, _)| s == serial)
        .map(|(_, st)| st.as_str())
        .ok_or_else(|| anyhow!("device disappeared during probe"))?;

    let authorized = state == "device";
    let ce_unlocked = if authorized {
        adb_shell(resolver, serial, &["cmd", "user", "is-user-unlocked", "0"])
            .map(|v| v.eq_ignore_ascii_case("true"))
    } else {
        None
    };
    let root = if authorized {
        adb_shell(resolver, serial, &["id"]).map(|v| v.contains("uid=0(root)"))
    } else {
        None
    };
    let bootloader_locked = if authorized {
        getprop(resolver, serial, "ro.boot.flash.locked").map(|v| v == "1")
    } else {
        None
    };

    let mut notes = Vec::new();
    if !authorized {
        notes.push(format!("ADB state is {state}"));
    }
    let access_state = match ce_unlocked {
        Some(true) => "adb_authorized_ce_unlocked".to_string(),
        Some(false) => "adb_authorized_direct_boot_bfu_limited".to_string(),
        None if authorized => "adb_authorized_state_unknown".to_string(),
        None => format!("adb_{state}"),
    };

    if ce_unlocked == Some(false) {
        notes.push("Credential-encrypted user storage reports locked; treat as BFU/Direct-Boot limited and do not reboot as part of acquisition.".into());
    }

    let info = DeviceInfo {
        platform: Platform::Android,
        identifier: serial.to_string(),
        manufacturer: authorized.then(|| getprop(resolver, serial, "ro.product.manufacturer")).flatten(),
        model: authorized.then(|| getprop(resolver, serial, "ro.product.model")).flatten(),
        device_name: authorized.then(|| getprop(resolver, serial, "ro.product.name")).flatten(),
        os_version: authorized.then(|| getprop(resolver, serial, "ro.build.version.release")).flatten(),
        build: authorized.then(|| getprop(resolver, serial, "ro.build.fingerprint")).flatten(),
        serial_number: Some(serial.to_string()),
        pairing_or_adb_authorized: Some(authorized),
        ce_unlocked_since_boot: ce_unlocked,
        root_or_jailbreak_detected: root,
        bootloader_locked,
        access_state,
        notes,
    };

    let capabilities = vec![
        Capability {
            name: "quick".into(),
            available: authorized,
            reason: if authorized { "ADB shell available" } else { "ADB not authorized" }.into(),
        },
        Capability {
            name: "logical_shared_storage".into(),
            available: authorized,
            reason: if authorized { "ADB pull of OS-exposed shared storage is available" } else { "ADB not authorized" }.into(),
        },
        Capability {
            name: "root_filesystem".into(),
            available: root == Some(true),
            reason: if root == Some(true) { "Existing root detected" } else { "No existing root detected; tool will not root the device" }.into(),
        },
    ];

    Ok(ProbeResult { device: info, capabilities })
}

pub fn adb_path(resolver: &ToolResolver) -> Result<std::path::PathBuf> {
    resolver
        .adb()
        .ok_or_else(|| anyhow!("adb not found. Install Android Platform Tools or pass --adb <path>."))
}

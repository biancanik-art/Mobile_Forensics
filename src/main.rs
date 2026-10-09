mod acquisition;
mod android;
mod case;
mod command;
mod hashing;
mod ios;
mod models;
mod tooling;

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};

use acquisition::{acquire_android, acquire_ios};
use android::{inspect_android, list_android_devices};
use ios::{inspect_ios, list_ios_devices};
use models::Profile;
use tooling::{safe_ios_tools, ToolResolver};

#[derive(Debug, Parser)]
#[command(name = "mobile-acquire")]
#[command(version)]
#[command(about = "Standalone forensic-first Android/iOS acquisition orchestrator")]
struct Cli {
    /// Directory containing libimobiledevice executables. Can also be set with MOBILE_ACQUIRE_IOS_TOOLS.
    #[arg(long, global = true)]
    ios_tools_dir: Option<PathBuf>,

    /// Explicit path to adb/adb.exe.
    #[arg(long, global = true)]
    adb: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check backend tools and print versions/paths. Does not contact a phone.
    Doctor {
        #[arg(long, value_enum, default_value = "all")]
        platform: PlatformArg,
    },

    /// Detect connected devices and report acquisition capabilities without changing trust state.
    Probe {
        #[arg(long, value_enum, default_value = "all")]
        platform: PlatformArg,

        /// Android serial or iOS UDID. When omitted, all detected devices are reported.
        #[arg(long)]
        device: Option<String>,

        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Acquire one connected device using a forensic acquisition profile.
    Acquire {
        #[arg(long, value_enum)]
        platform: PlatformArg,

        /// Android serial or iOS UDID. Required when multiple devices are attached.
        #[arg(long)]
        device: Option<String>,

        #[arg(long, value_enum, default_value = "quick")]
        profile: ProfileArg,

        #[arg(long)]
        case_id: String,

        #[arg(long)]
        evidence_id: String,

        #[arg(long)]
        examiner: String,

        #[arg(long, default_value = ".")]
        output: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PlatformArg {
    All,
    Android,
    Ios,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    Quick,
    Logical,
    Enhanced,
}

impl From<ProfileArg> for Profile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Quick => Profile::Quick,
            ProfileArg::Logical => Profile::Logical,
            ProfileArg::Enhanced => Profile::Enhanced,
        }
    }
}

fn doctor(resolver: &ToolResolver, platform: PlatformArg) {
    if matches!(platform, PlatformArg::All | PlatformArg::Android) {
        let tool = resolver.describe_adb();
        println!("Android:");
        println!("  adb: {}", if tool.available { "FOUND" } else { "MISSING" });
        if let Some(path) = tool.path {
            println!("    path: {path}");
        }
        if let Some(version) = tool.version {
            println!("    version: {version}");
        }
    }

    if matches!(platform, PlatformArg::All | PlatformArg::Ios) {
        println!("iOS / libimobiledevice:");
        for name in safe_ios_tools() {
            let tool = resolver.describe_ios(name);
            println!("  {name}: {}", if tool.available { "FOUND" } else { "MISSING" });
            if let Some(path) = tool.path {
                println!("    path: {path}");
            }
            if let Some(version) = tool.version {
                println!("    version: {version}");
            }
        }
    }
}

fn probe_android_all(resolver: &ToolResolver, requested: Option<&str>, json: bool) -> Result<()> {
    let devices = list_android_devices(resolver)?;
    let mut results = Vec::new();
    for (serial, _) in devices {
        if requested.is_some_and(|wanted| wanted != serial) {
            continue;
        }
        results.push(inspect_android(resolver, &serial)?);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else if results.is_empty() {
        println!("No matching Android devices detected.");
    } else {
        for r in results {
            println!("{}", r.device.identifier);
            println!("  model={:?}", r.device.model);
            println!("  os={:?}", r.device.os_version);
            println!("  access_state={}", r.device.access_state);
            for c in r.capabilities {
                println!("  {}={} ({})", c.name, c.available, c.reason);
            }
        }
    }
    Ok(())
}

fn probe_ios_all(resolver: &ToolResolver, requested: Option<&str>, json: bool) -> Result<()> {
    let devices = list_ios_devices(resolver)?;
    let mut results = Vec::new();
    for udid in devices {
        if requested.is_some_and(|wanted| wanted != udid) {
            continue;
        }
        results.push(inspect_ios(resolver, &udid)?);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else if results.is_empty() {
        println!("No matching iOS devices detected.");
    } else {
        for r in results {
            println!("{}", r.device.identifier);
            println!("  model={:?}", r.device.model);
            println!("  os={:?}", r.device.os_version);
            println!("  access_state={}", r.device.access_state);
            for c in r.capabilities {
                println!("  {}={} ({})", c.name, c.available, c.reason);
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let resolver = ToolResolver::new(cli.ios_tools_dir, cli.adb);

    match cli.command {
        Commands::Doctor { platform } => doctor(&resolver, platform),
        Commands::Probe {
            platform,
            device,
            json,
        } => match platform {
            PlatformArg::Android => probe_android_all(&resolver, device.as_deref(), json)?,
            PlatformArg::Ios => probe_ios_all(&resolver, device.as_deref(), json)?,
            PlatformArg::All => {
                if json {
                    bail!("--json with --platform all is intentionally disabled in v0.2.0; probe one platform at a time for machine-readable output")
                }
                println!("=== Android ===");
                if let Err(err) = probe_android_all(&resolver, device.as_deref(), false) {
                    println!("Android probe unavailable: {err:#}");
                }
                println!("\n=== iOS ===");
                if let Err(err) = probe_ios_all(&resolver, device.as_deref(), false) {
                    println!("iOS probe unavailable: {err:#}");
                }
            }
        },
        Commands::Acquire {
            platform,
            device,
            profile,
            case_id,
            evidence_id,
            examiner,
            output,
        } => {
            let profile: Profile = profile.into();
            match platform {
                PlatformArg::Android => acquire_android(
                    &resolver,
                    device.as_deref(),
                    profile,
                    &case_id,
                    &evidence_id,
                    &examiner,
                    &output,
                )?,
                PlatformArg::Ios => acquire_ios(
                    &resolver,
                    device.as_deref(),
                    profile,
                    &case_id,
                    &evidence_id,
                    &examiner,
                    &output,
                )?,
                PlatformArg::All => bail!("--platform all is valid only for doctor/probe"),
            }
        }
    }

    Ok(())
}

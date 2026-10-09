use std::path::PathBuf;

use crate::command::{find_executable, version_of};
use crate::models::ToolInfo;

#[derive(Debug, Clone)]
pub struct ToolResolver {
    pub ios_dir: Option<PathBuf>,
    pub adb_override: Option<PathBuf>,
}

impl ToolResolver {
    pub fn new(ios_dir: Option<PathBuf>, adb_override: Option<PathBuf>) -> Self {
        let ios_dir = ios_dir.or_else(|| {
            std::env::var_os("MOBILE_ACQUIRE_IOS_TOOLS").map(PathBuf::from)
        });
        Self {
            ios_dir,
            adb_override,
        }
    }

    pub fn ios(&self, name: &str) -> Option<PathBuf> {
        find_executable(name, self.ios_dir.as_deref())
    }

    pub fn adb(&self) -> Option<PathBuf> {
        if let Some(p) = &self.adb_override {
            if p.is_file() {
                return Some(p.clone());
            }
        }
        find_executable("adb", None)
    }

    pub fn describe_ios(&self, name: &str) -> ToolInfo {
        describe(name, self.ios(name))
    }

    pub fn describe_adb(&self) -> ToolInfo {
        describe("adb", self.adb())
    }
}

fn describe(name: &str, path: Option<PathBuf>) -> ToolInfo {
    let version = path.as_deref().and_then(version_of);
    ToolInfo {
        name: name.to_string(),
        available: path.is_some(),
        path: path.as_ref().map(|p| p.display().to_string()),
        version,
    }
}

pub fn safe_ios_tools() -> &'static [&'static str] {
    &[
        "idevice_id",
        "ideviceinfo",
        "idevicepair",
        "idevicebackup2",
        "idevicecrashreport",
        "idevicesyslog",
        "ideviceprovision",
        "afcclient",
    ]
}

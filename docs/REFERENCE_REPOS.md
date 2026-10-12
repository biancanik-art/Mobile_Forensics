# Reference repositories

These repositories are used as implementation references and test checklists. Mobile Forensics does not vendor their source code.

## DouglasFreshHabian/AndroidForensics

Source: https://github.com/DouglasFreshHabian/AndroidForensics

The repository is MIT-licensed and documents a broad ADB triage workflow. Mobile Forensics independently implements a subset of the useful read-only acquisition surfaces, including:

- package and service inventory
- account, battery, power, location, telecom, USB and system-event dumps
- memory, sensors, audio, package, window and system-statistics dumps
- settings, usage, notification, connectivity, network and Wi-Fi state
- best-effort contacts, call-log, SMS and MMS content-provider queries in the Enhanced profile

The AirScope workflow in that repository disables and re-enables Wi-Fi before collecting scan information. Mobile Forensics intentionally does **not** reproduce that behavior because toggling a radio changes device state. We collect passive `dumpsys wifi` output instead.

## DouglasFreshHabian/iOS

Source: https://github.com/DouglasFreshHabian/iOS

This repository is a command/reference collection for libimobiledevice, pymobiledevice3, MVT and related tools. No LICENSE file was present at the repository root when reviewed, so Mobile Forensics treats it strictly as a reference and does not copy its scripts or other source files.

Useful read-only ideas independently implemented or tracked include:

- `ideviceinfo -s` and full device information
- battery-domain information through `ideviceinfo`
- pairing validation without creating a new pairing
- installed-application inventory when `ideviceinstaller` is present
- MobileBackup2 acquisition
- crash-report copying while keeping source reports
- AFC read acquisition (tracked for real-device validation)
- pymobiledevice3 as an optional secondary backend

The following state-changing examples from the reference repository are intentionally excluded from automatic acquisition:

- enabling/changing iOS backup encryption
- `afcclient put`
- creating a new pairing
- changing the device name
- shutdown or restart
- enabling diagnostic features
- provisioning-profile installation/removal

## MVT

Mobile Verification Toolkit remains a downstream analysis tool and methodological reference. It is not linked, vendored, imported, or required by Mobile Forensics.

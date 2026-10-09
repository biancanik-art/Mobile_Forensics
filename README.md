# Mobile Forensics

Standalone forensic-first phone acquisition project for Android and iOS.

The acquisition engine is independent from KDFT. Its goal is to preserve native artifacts, record what was requested and what succeeded, hash resulting evidence, and clearly report acquisition limits. Analysis is intentionally out of scope.

Current acquisition backends:
- Android Platform Tools (`adb`)
- libimobiledevice for iPhone/iPad

The project never automatically reboots a phone, enters recovery/DFU, unlocks a bootloader, roots or jailbreaks a device, creates a new iOS trust relationship, changes backup-encryption settings, restores firmware/data, or installs/removes provisioning profiles.

See `docs/IOS_BACKEND.md` and `docs/ROADMAP.md` for the acquisition design and next milestones.

# Mobile Forensics

Standalone forensic-first phone acquisition project for Android and iOS.

The acquisition engine is independent from KDFT and does not embed Mobile Verification Toolkit (MVT). Its goal is to preserve native/raw artifacts, record what was requested and what succeeded, hash resulting evidence, and clearly report acquisition limits. Analysis is intentionally out of scope.

Current acquisition backends:
- Android Platform Tools (`adb`)
- libimobiledevice for iPhone/iPad
- optional pymobiledevice3 detection as a secondary iOS backend

Current evidence output includes:
- device and capability metadata
- backend/tool inventory
- actions and errors as JSONL
- per-artifact acquisition records in `artifacts.jsonl`
- SHA-256 evidence manifest and manifest integrity record
- native Android/iOS acquisition output kept without parsing

The project never automatically reboots a phone, enters recovery/DFU, unlocks a bootloader, roots or jailbreaks a device, creates a new iOS trust relationship, changes backup-encryption settings, restores firmware/data, or installs/removes provisioning profiles.

The project may produce artifacts that downstream tools such as MVT, ALEAPP, iLEAPP, Autopsy or other forensic suites can analyze, but those analyzers are separate from the acquisition engine.

See `docs/IOS_BACKEND.md`, `docs/THIRD_PARTY_POLICY.md`, and `docs/ROADMAP.md` for acquisition design and next milestones.

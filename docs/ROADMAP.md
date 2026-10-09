# Roadmap

## v0.3 acquisition integrity

- streaming SHA-256 during file-level transfers where the transport exposes bytes directly
- per-object JSONL manifest with source path, destination path, size, method and status
- acquisition checkpoint/resume state
- disconnect detection and explicit resume workflow
- destination free-space preflight
- evidence-container finalization without circular metadata hashes

## v0.4 iOS

- validated non-interactive AFC recursive Media export
- HouseArrest document export for file-sharing apps
- optional sysdiagnose collection workflow where the user/device state already permits it
- pairing-record import/export workflow without silently creating trust
- capability tests by iOS version and lock state

## v0.5 Android

- APK export with package-to-source provenance
- selected content-provider acquisition through a consented collector plugin
- existing-root filesystem streaming
- raw block-device streaming when pre-existing privileges expose readable block devices

## Advanced acquisition plugins

Device-specific low-level methods stay isolated from the normal acquisition engine. A plugin must declare supported models/OS builds, required device state, modifications, failure modes, and exact acquisition class. No plugin may label an acquisition "full filesystem" or "physical" unless the data surface actually matches that claim.

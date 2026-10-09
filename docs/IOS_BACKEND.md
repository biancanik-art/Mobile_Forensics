# iOS backend design

Mobile Acquire treats libimobiledevice as an external acquisition backend. This keeps the standalone Rust codebase independent while using the mature native-protocol implementation maintained by the libimobiledevice project.

## Forensic policy

The backend divides libimobiledevice commands into three groups.

### Allowed read/copy operations

- `idevice_id -l`
- `ideviceinfo -s -u <UDID>`
- `ideviceinfo -u <UDID>` only after an existing pairing validates
- `idevicepair -u <UDID> validate`
- `idevicebackup2 -u <UDID> backup --full <directory>`
- `idevicecrashreport -u <UDID> -k <directory>`
- `idevicesyslog -u <UDID> archive <path>`
- `ideviceprovision -u <UDID> list`
- `ideviceprovision -u <UDID> copy <directory>`

### Detected but not yet automated

- AFC recursive export through `afcclient`
- HouseArrest per-app document/container export

These are useful acquisition surfaces, but the v0.2 implementation intentionally waits for device-level validation of the non-interactive command transport before enabling them.

### Never invoked automatically

- `idevicepair pair`
- `idevicepair unpair`
- `ideviceenterrecovery`
- restore/erase operations
- `idevicename` set
- `idevicedate` set
- `idevicesetlocation`
- provisioning install/remove/remove-all
- image mounting

## Access-state terminology

The tool reports what it can prove:

- USB visible
- existing pairing valid/invalid/unknown
- service/capability availability

It does **not** label an iPhone AFU or BFU only because a lockdownd service succeeds or fails. A forensic examiner may record AFU/BFU independently from observed device state.

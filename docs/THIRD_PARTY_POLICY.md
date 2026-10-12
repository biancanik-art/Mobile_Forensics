# Third-party policy

Mobile Forensics is an acquisition tool, not an embedded distribution of Mobile Verification Toolkit (MVT).

## MVT

MVT is treated as a downstream analysis tool and a methodological reference. Mobile Forensics does not copy MVT source code, import it as a library, or require it for acquisition. Raw/native artifacts should remain usable by MVT or other analysis tools where their normal input formats overlap.

Concepts such as preserving raw artifacts, separating acquisition from analysis, and reporting incomplete collections are implemented independently in this repository.

## iOS transport tools

libimobiledevice is used as an external command-line backend for Apple device protocols. pymobiledevice3 is detected as an optional secondary backend. Backend identity and versions are written to the case metadata so a transport switch is explicit and auditable.

The acquisition engine does not silently create a pairing relationship or change backup-encryption state.

## Android transport tools

Android Platform Tools/ADB is used as an external backend. The tool preserves raw output from independent system surfaces rather than requiring an analysis framework during acquisition.

## Licensing

Each external backend remains subject to its own license and installation terms. Mobile Forensics source code remains separately licensed under Apache-2.0. This document describes project architecture and is not legal advice.

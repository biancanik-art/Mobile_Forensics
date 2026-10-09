$ErrorActionPreference = 'Stop'

Write-Host 'Checking Rust toolchain...'
rustc --version
cargo --version

Write-Host 'Formatting...'
cargo fmt --all -- --check

Write-Host 'Checking...'
cargo check

Write-Host 'Testing...'
cargo test

Write-Host 'Clippy...'
cargo clippy --all-targets -- -D warnings

Write-Host 'Building release...'
cargo build --release

Write-Host "Built: $PSScriptRoot\..\target\release\mobile-acquire.exe"

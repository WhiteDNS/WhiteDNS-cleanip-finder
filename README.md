# WhiteDNS Go Port

WhiteDNS Go Port is the Go implementation of WhiteDNS with native scanning, proxy workflows, and terminal UI support.

## Features

- Native scanner pipeline (CIDR expansion, port probing, concurrency control, result export)
- White routing and DPI-related workflows in terminal UI
- TCP proxy, HTTP CONNECT tunneling, and SOCKS5 support
- ASN-aware target handling
- Cross-platform builds for Windows, Linux, macOS, and Termux/Android

## Standalone Runtime

- Build artifacts are standalone binaries.
- ASN datasets and assets/cf-domains.txt are embedded in the executable.
- Config maker uses user-provided input or user-provided files and writes output to app data at runtime.

## Requirements

- Go 1.20+
- PowerShell (Windows) or bash (Linux/macOS)

## Run Locally

Run TUI mode:

```powershell
go run ./cmd/whitedns -mode ui -host 0.0.0.0 -port 7080
```

Run proxy-only mode:

```powershell
go run ./cmd/whitedns -mode proxy -host 0.0.0.0 -port 7080
```

Run tests:

```powershell
go test ./...
```

## Build

Build all targets:

```powershell
./build_cross_platform.ps1 -CleanBuild
```

Single target build example:

```powershell
go build -o builds/whitedns-windows-amd64.exe ./cmd/whitedns
```

Expected cross-platform outputs in builds:

- whitedns-windows-amd64.exe
- whitedns-linux-amd64
- whitedns-linux-arm64
- whitedns-macos-amd64
- whitedns-macos-arm64
- whitedns-termux-arm64

## Project Layout

- cmd/whitedns: application entrypoint
- internal/ui: terminal UI and workflow screens
- internal/scanner: scanning engine and probe logic
- internal/asn: ASN loading and lookup engine
- internal/bundledata: embedded runtime datasets/assets
- internal/proxy: proxy server components
- internal/router: routing and persistence logic

## Contributing

1. Create a branch.
2. Run tests with go test ./....
3. Build with build_cross_platform.ps1 or go build.
4. Open a pull request with a clear summary.

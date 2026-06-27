# WhiteDNS Clean IP Finder

<p align="center">
  <img src="android/app/src/main/res/drawable-nodpi/whitedns_logo.png" alt="WhiteDNS IP Scanner" width="150">
</p>

<p align="center">
  <strong>Desktop 1.2 and Android 1.2 clean-IP scanner, proxy checker, ASN target expander, and WhiteDNS toolkit.</strong>
</p>

<p align="center">
  <a href="README.md"><strong>English</strong></a>
  ·
  <a href="README.fa.md"><strong>فارسی</strong></a>
  ·
  <a href="https://github.com/tajirax/WhiteDNS-cleanip-finder/releases"><strong>Downloads</strong></a>
</p>

---

## Latest Releases

| Release | Platform | What You Get | Best For |
|---|---|---|---|
| **WhiteDNS Desktop 1.2** | Windows, Linux, macOS, Termux | Terminal UI, proxy tools, scanner engine, config workflows, cross-platform binaries | Power users, desktop scanning, bulk workflows |
| **WhiteDNS IP Scanner Android 1.2** | Android API 21+ | Native Android app, IP/CIDR scanner, SNI scanner, HTTP/SOCKS5 proxy scanner, ASN export, signed APK/AAB outputs | Phone-based scanning and portable clean-IP discovery |

Download the latest files from the **GitHub Releases** page:

```text
https://github.com/tajirax/WhiteDNS-cleanip-finder/releases
```

---

## What WhiteDNS Does

WhiteDNS is a clean-IP discovery and proxy workflow toolkit. It expands IP ranges, scans ports, tests TLS/SNI behavior, verifies HTTP and SOCKS5 proxies, exports ASN targets, and saves results in a format that is easy to reuse in proxy and routing workflows.

### Key Features

- Native Go scanner engine with CIDR expansion, concurrency control, pause/resume, stop, progress, and result export.
- Desktop terminal UI for scanning, routing, DPI/desync-related workflows, config tools, and proxy operations.
- Android app with IP/CIDR scan, SNI scan, HTTP proxy scan, SOCKS5 scan, ASN export, foreground service scanning, and storage export.
- ASN-aware target handling using embedded datasets.
- Standalone desktop builds with embedded runtime assets.
- Android multi-ABI builds: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`, universal APK, and release AAB.

---

## Desktop 1.2 Guide

### Download

Go to **Releases** and download the file for your operating system:

| OS | Asset |
|---|---|
| Windows | `whitedns-windows-amd64.exe` |
| Linux x64 | `whitedns-linux-amd64` |
| Linux ARM64 | `whitedns-linux-arm64` |
| macOS Intel | `whitedns-macos-amd64` |
| macOS Apple Silicon | `whitedns-macos-arm64` |
| Termux / Android ARM64 | `whitedns-termux-arm64` |

### Run

Windows PowerShell:

```powershell
.\whitedns-windows-amd64.exe -mode ui -host 0.0.0.0 -port 8080
```

Linux/macOS:

```bash
chmod +x ./whitedns-linux-amd64
./whitedns-linux-amd64 -mode ui -host 0.0.0.0 -port 8080
```

Proxy-only mode:

```bash
./whitedns-linux-amd64 -mode proxy -host 0.0.0.0 -port 8080
```

### Desktop Notes

- Results and logs are written beside the executable in WhiteDNS output folders.
- ASN datasets and Cloudflare domain assets are embedded in the binary.
- Use the TUI for the full workflow experience.
- Use proxy mode when you only need the local proxy/tunnel behavior.

---

## Android 1.2 Guide

### Download

From **Releases**, download one of the Android artifacts:

| Artifact | Use Case |
|---|---|
| `WhiteDNS-IP-Scanner-universal-release.apk` | Recommended direct install for most users |
| `WhiteDNS-IP-Scanner-arm64-v8a-release.apk` | Most modern Android phones |
| `WhiteDNS-IP-Scanner-armeabi-v7a-release.apk` | Older 32-bit ARM devices |
| `WhiteDNS-IP-Scanner-x86-release.apk` / `x86_64` | Emulator and x86 devices |
| `WhiteDNS-IP-Scanner-release.aab` | Play Store upload |

### Install

1. Download the APK to your phone.
2. Open it from your file manager.
3. Allow installation from your browser/file manager if Android asks.
4. Open **WhiteDNS IP Scanner**.
5. Grant storage/folder access if you want the app to create and write to the public `WhiteDNS Scanner` folder.

### Android Features

- IP / CIDR Scan
- SNI Scanner
- HTTP Proxy Scan
- SOCKS5 Scan
- ASN Export
- Pause / Resume / Stop scanning
- Results, logs, and ASN exports saved under `WhiteDNS Scanner`

### Android Storage Output

When folder access is granted, WhiteDNS writes to a user-visible folder:

```text
/sdcard/WhiteDNS Scanner/
```

Fallback/app-specific location:

```text
/sdcard/Android/data/com.whitescan.app/files/WhiteDNS Scanner/
```

---

## Build From Source

### Requirements

- Go 1.25+
- PowerShell on Windows, or bash on Linux/macOS
- For Android: JDK 17, Android SDK API 34, NDK r26, Gradle 8.7, gomobile

### Desktop Build

Build all desktop targets:

```powershell
.\build_cross_platform.ps1 -CleanBuild
```

Run tests:

```powershell
go test ./...
```

### Android Build

Build the Go mobile AAR:

```powershell
.\build-aar.ps1
```

Build Android from the `android` folder:

```powershell
cd android
gradle assembleRelease bundleRelease
```

For complete Android build instructions, see:

```text
android/README.md
```

---

## Project Layout

| Path | Purpose |
|---|---|
| `cmd/whitedns` | Desktop application entrypoint |
| `internal/ui` | Terminal UI and workflow screens |
| `internal/scanner` | Scanner engine, probes, pause/resume, proxy scanning |
| `internal/asn` | ASN loading and lookup |
| `internal/bundledata` | Embedded datasets and runtime assets |
| `internal/proxy` | Proxy server components |
| `mobile` | Go mobile bridge used by Android |
| `android` | Native Android app |

---

## Contributing

1. Create a branch.
2. Run `go test ./...`.
3. Build the affected target.
4. Open a pull request with a clear summary and test notes.

---

## Disclaimer

Use WhiteDNS only on networks, hosts, and ranges you own or have permission to test. You are responsible for complying with local laws, provider rules, and network policies.

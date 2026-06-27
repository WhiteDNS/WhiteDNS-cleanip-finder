# WhiteDNS Android — Build Guide

## Prerequisites (one-time setup)

### 1. JDK 17
Download from https://adoptium.net and install. Verify:
```
java -version   # must say 17.x
```

### 2. Android SDK + NDK
Install **Android Studio** (includes SDK). Then in **SDK Manager**:
- **SDK Platforms**: Android 14 (API 34) and Android 5.0 (API 21)
- **SDK Tools**: NDK (Side by side) ≥ r26, CMake

Set environment variables:
```powershell
$env:ANDROID_HOME = "C:\Users\<you>\AppData\Local\Android\Sdk"
$env:ANDROID_NDK_HOME = "$env:ANDROID_HOME\ndk\<version>"
```
Add both to your user PATH permanently via System Properties.

### 3. Go toolchain + gomobile
```powershell
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init
```
`gomobile init` downloads the Android NDK-linked Go runtime. It needs ANDROID_NDK_HOME set.

---

## Build the engine .aar

From the **repo root** (`go-port/`):
```powershell
.\build-aar.ps1
```
This produces `android/app/libs/whitescan.aar`. The file is ~20–30 MB (arm64 + arm + x86_64).

Re-run this any time you change Go engine code. The Gradle build picks it up automatically.

---

## Open and run the Android app

1. Open **Android Studio** → `android/` folder (this directory).
2. Let Gradle sync (it reads `whitescan.aar` from `app/libs/`).
3. Connect a device (API 21+) or start an emulator.
4. Run the `app` configuration.

---

## Known Android limitations vs desktop TUI

| Feature | Desktop | Android |
|---|---|---|
| Masscan / Nmap preflight | ✓ | ✗ (direct scan only) |
| DPI / desync config | ✓ | ✗ (not in scope) |
| File descriptor limit | OS default | Android caps at ~1024; engine auto-detects |
| Concurrency | Up to 5000 | Recommend ≤500 for devices |

## File outputs

Results are saved to `filesDir/results/scan-<type>-<timestamp>.txt`.
On a device: **Files → WhiteDNS → results/**.
Use the **Share** button in the Results screen to export via any app.

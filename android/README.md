# WhiteDNS Android — Build Guide

Two ways to get an APK:

- **A. GitHub Actions (no local setup)** — push a `v*` tag or run the workflow
  manually; download the APK artifact. See the bottom of this file.
- **B. Local build** — everything below.

---

## A note on the toolchain quirks (read this first)

The repo's `go.mod` may declare a `go` directive newer than your installed Go.
Two things keep the build working — both are already baked into `build-aar.ps1`
and the CI workflow, but if you run commands by hand you need them:

```powershell
$env:GOTOOLCHAIN = "local"          # never auto-download a Go version
go get -tool golang.org/x/mobile/cmd/gobind   # Go 1.25+ needs gomobile in the tool graph
```

You also need **Go 1.25+** because recent `gomobile` requires it.

---

## Prerequisites (one-time setup)

### 1. JDK 17
Download from https://adoptium.net and install. Verify:
```powershell
java -version   # must say 17.x
```

### 2. Android SDK + NDK
Install **Android Studio** (includes the SDK). Then in **SDK Manager**:
- **SDK Platforms**: Android 14 (API 34) and Android 5.0 (API 21)
- **SDK Tools**: NDK (Side by side) **r26** (`26.3.11579264`), CMake, Build-Tools 34

Set environment variables (PowerShell, current session):
```powershell
$env:ANDROID_HOME     = "$env:LOCALAPPDATA\Android\Sdk"
$env:ANDROID_NDK_HOME = "$env:ANDROID_HOME\ndk\26.3.11579264"
```
Add both permanently via **System Properties → Environment Variables** so new
shells inherit them.

### 3. Go 1.25+ and gomobile
```powershell
go version    # must be >= 1.25
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init     # downloads the NDK-linked Go runtime; needs ANDROID_NDK_HOME
```
Make sure `%USERPROFILE%\go\bin` is on your PATH so `gomobile` is found.

---

## Build — step by step

All commands run from the **repo root** (`go-port/`).

### Step 1 — Build the engine `.aar`
```powershell
.\build-aar.ps1
```
This sets `GOTOOLCHAIN=local`, registers the gomobile tool dependency, then runs
`gomobile bind` for **armeabi-v7a, arm64-v8a, x86, x86_64**. Output:
`android/app/libs/whitescan.aar` (~20–30 MB).

Re-run this whenever you change Go code under `mobile/` or `internal/`.

### Step 2 — Build the APK

**Option 1 — Android Studio (easiest):**
1. Open the `android/` folder in Android Studio.
2. Let Gradle sync (it reads `whitescan.aar` from `app/libs/`).
3. Connect a device (API 21+) or start an emulator → Run `app`.

**Option 2 — Command line (no IDE):**
```powershell
cd android
.\gradlew.bat assembleDebug      # or: gradle assembleDebug  (if Gradle is on PATH)
```
The APK lands at:
```
android/app/build/outputs/apk/debug/app-debug.apk
```
Install on a connected device:
```powershell
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

> If there's no `gradlew.bat`, install Gradle 8.7 and use `gradle assembleDebug`,
> or open the project once in Android Studio to generate the wrapper.

---

## Toolchain versions (must match for a clean build)

| Tool | Version |
|---|---|
| Go | 1.25+ |
| JDK | 17 |
| Android Gradle Plugin | 8.5.2 |
| Gradle | 8.7 |
| Kotlin | 1.9.24 |
| Compose Compiler ext | 1.5.14 (Compose BOM 2024.06.00) |
| NDK | r26 (26.3.11579264) |
| compileSdk / minSdk | 34 / 21 |

Kotlin must stay on **1.9.x** — Kotlin 2.0 drops the legacy
`kotlinCompilerExtensionVersion` mechanism this project uses.

---

## File outputs on the device

All results, logs, and ASN exports are written under a **`WhiteDNS Scanner`**
folder in the app's external files dir (no storage permission needed):
```
/sdcard/Android/data/com.whitescan.app/files/WhiteDNS Scanner/
    results/      scan-<type>-<timestamp>.txt
    asn_exports/
    logs/
```
On the device: **Files → Android → data → com.whitescan.app → files →
WhiteDNS Scanner**. Or use the **Share** button on the Results screen to export
via any app. Results are streamed to disk as they're found, so memory stays low
even on million-IP scans.

---

## Known Android limitations vs the desktop TUI

| Feature | Desktop | Android |
|---|---|---|
| Masscan / Nmap preflight | ✓ | ✗ (direct scan only) |
| DPI / desync config | ✓ | ✗ (not in scope) |
| File-descriptor limit | OS default | Android caps ~1024; mobile bridge caps concurrency at 300 |
| Concurrency | up to 5000 | presets up to 5000, but ≤500 recommended on phones |

---

## B. Build via GitHub Actions (no local setup)

The workflow at `.github/workflows/build-apk.yml` does the whole pipeline on a
clean Ubuntu runner. It builds signed release artifacts for `armeabi-v7a`,
`arm64-v8a`, `x86`, `x86_64`, a universal APK, and a release AAB for Play Store.

Add these repository secrets before running the release workflow:

- `TAJIRAX_KEYSTORE_BASE64`: base64-encoded `.jks` release keystore.
- `TAJIRAX_KEYSTORE_PASSWORD`: keystore password.
- `TAJIRAX_KEY_ALIAS`: key alias; defaults to `tajirax` if omitted.
- `TAJIRAX_KEY_PASSWORD`: key password; defaults to the keystore password if omitted.

- **Manual:** GitHub → **Actions** → **Build Android APK** → **Run workflow**.
- **On a release tag:**
  ```powershell
  git tag v1.0.0
  git push origin v1.0.0
  ```

When it finishes, the signed release files are on the run's page under
**Artifacts** (`WhiteDNS-IP-Scanner-<sha>-signed-release`). Tag builds also
publish a GitHub **Release** with the APKs and AAB attached.

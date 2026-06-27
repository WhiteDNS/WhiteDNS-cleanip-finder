# Builds the Go scanner engine into an Android .aar via gomobile.
#
# Prerequisites (see android/README.md for details):
#   - JDK 17+            (java on PATH)
#   - Android SDK + NDK  (ANDROID_HOME / ANDROID_NDK_HOME set)
#   - gomobile:          go install golang.org/x/mobile/cmd/gomobile@latest
#                        go install golang.org/x/mobile/cmd/gobind@latest
#                        gomobile init
#
# Output: android/app/libs/whitescan.aar (+ sources jar)

$ErrorActionPreference = "Stop"

$repoRoot = $PSScriptRoot
$outDir   = Join-Path $repoRoot "android/app/libs"
$outAar   = Join-Path $outDir "whitescan.aar"
$goBin    = Join-Path $env:USERPROFILE "go/bin"

if ((Test-Path $goBin) -and (($env:PATH -split ';') -notcontains $goBin)) {
    $env:PATH = "$goBin;$env:PATH"
}

if (-not (Get-Command gomobile -ErrorAction SilentlyContinue)) {
    Write-Error "gomobile not found on PATH. Run: go install golang.org/x/mobile/cmd/gomobile@latest; gomobile init"
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host "Building whitescan.aar (arm64-v8a, armeabi-v7a, x86_64)..." -ForegroundColor Cyan
$gomobileArgs = @(
    "bind",
    "-target=android/arm64,android/arm,android/amd64",
    "-androidapi", "21",
    "-javapkg", "com.whitescan.engine",
    "-o", $outAar,
    "./mobile"
)
& gomobile @gomobileArgs

if ($LASTEXITCODE -ne 0) { Write-Error "gomobile bind failed ($LASTEXITCODE)" }
Write-Host "OK -> $outAar" -ForegroundColor Green

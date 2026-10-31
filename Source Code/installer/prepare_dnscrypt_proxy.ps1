$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Version = '2.1.20'
$ArchiveName = "dnscrypt-proxy-win64-$Version.zip"
$DownloadUrl = "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/$Version/$ArchiveName"
$ExpectedSha256 = '9E498CB9BDBAE57756DB19CE516362AC307E9340A6996214964CFCC7C489ABC3'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DownloadDir = Join-Path $ScriptDir 'downloads'
$PayloadRoot = Join-Path $ScriptDir 'payload'
$PayloadDir = Join-Path $PayloadRoot 'dnscrypt-proxy'
$ArchivePath = Join-Path $DownloadDir $ArchiveName
$ExtractDir = Join-Path $DownloadDir "extract-$Version"

New-Item -ItemType Directory -Force -Path $DownloadDir, $PayloadRoot | Out-Null

if (Test-Path -LiteralPath $ArchivePath) {
    $existingHash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($existingHash -ne $ExpectedSha256) {
        Write-Host 'Cached DNSCrypt Proxy archive has an unexpected hash; removing it.' -ForegroundColor Yellow
        Remove-Item -LiteralPath $ArchivePath -Force
    }
}

if (-not (Test-Path -LiteralPath $ArchivePath)) {
    Write-Host "Downloading official DNSCrypt Proxy $Version Windows x64 archive..."
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ArchivePath -UseBasicParsing -TimeoutSec 120
    } catch {
        throw "Could not download $DownloadUrl. Check internet access and try again. Details: $($_.Exception.Message)"
    }
}

$actualHash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actualHash -ne $ExpectedSha256) {
    Remove-Item -LiteralPath $ArchivePath -Force -ErrorAction SilentlyContinue
    throw "DNSCrypt Proxy archive SHA-256 mismatch. Expected $ExpectedSha256, got $actualHash. The archive was not extracted or packaged."
}
Write-Host "SHA-256 verified: $actualHash" -ForegroundColor Green

if (Test-Path -LiteralPath $ExtractDir) { Remove-Item -LiteralPath $ExtractDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractDir -Force

$exe = Get-ChildItem -LiteralPath $ExtractDir -Filter 'dnscrypt-proxy.exe' -File -Recurse | Select-Object -First 1
if (-not $exe) { throw 'The verified archive did not contain dnscrypt-proxy.exe; refusing to create a broken installer payload.' }

# Copy the extracted official package intact (including bundled licenses/readmes).
$stage = Join-Path $DownloadDir "payload-stage-$Version"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Get-ChildItem -LiteralPath $exe.Directory.FullName -Force | Copy-Item -Destination $stage -Recurse -Force

# Ensure the staged root exposes the executable at the expected stable path.
if (-not (Test-Path -LiteralPath (Join-Path $stage 'dnscrypt-proxy.exe'))) {
    Copy-Item -LiteralPath $exe.FullName -Destination (Join-Path $stage 'dnscrypt-proxy.exe') -Force
}

# Ensure the upstream license is included even if the Windows ZIP omits it.
$licenseFile = Get-ChildItem -LiteralPath $stage -Filter 'LICENSE*' -File -Recurse | Select-Object -First 1
if (-not $licenseFile) {
    $licensePath = Join-Path $stage 'LICENSE.txt'
    $licenseUrl = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-proxy/$Version/LICENSE"
    Invoke-WebRequest -Uri $licenseUrl -OutFile $licensePath -UseBasicParsing -TimeoutSec 30
    $licenseText = Get-Content -LiteralPath $licensePath -Raw
    if ($licenseText -notmatch 'ISC License') {
        throw 'The upstream license download did not contain the expected ISC License text; refusing to package it.'
    }
}

# Keep a clear notice even if a particular upstream archive omits a top-level license.
$notice = @"
DNSCrypt Proxy — third-party component
Upstream: https://github.com/DNSCrypt/dnscrypt-proxy
Version: $Version
Official Windows x64 archive: $DownloadUrl
Verified archive SHA-256: $ExpectedSha256

This component is provided separately from Raider DNS and remains subject to the upstream project's license and notices. See LICENSE* files included in this directory. Do not remove upstream copyright/licensing notices when redistributing it.
"@
Set-Content -LiteralPath (Join-Path $stage 'THIRD_PARTY_NOTICES.txt') -Value $notice -Encoding UTF8

if (Test-Path -LiteralPath $PayloadDir) { Remove-Item -LiteralPath $PayloadDir -Recurse -Force }
Move-Item -LiteralPath $stage -Destination $PayloadDir
Remove-Item -LiteralPath $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "DNSCrypt Proxy $Version staged at: $PayloadDir" -ForegroundColor Green
Write-Host 'This step only prepares installer files; it does not start DNSCrypt Proxy or change Windows DNS.'

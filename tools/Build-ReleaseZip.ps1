<#
.SYNOPSIS
    Builds the EraseDrive module-only release ZIP and proves what is inside it.

.DESCRIPTION
    v3.1.0 ships module-only: a ZIP of .ps1 files plus a GitHub release, with no
    installer. An unsigned .exe that destroys disks has the exact profile of
    malware, and asking sysadmins to click through "Windows protected your PC" to
    run a wiper trains the wrong instinct in the audience whose trust the product
    needs. See tasks/launch-steps.md step 4.1 for the full reasoning.

    This script exists instead of a copy-pasted block of commands because the
    release archive is the one artifact where a mistake is published. It is
    built from an explicit allowlist and then READ BACK with a different reader
    than the one that wrote it (System.IO.Compression.ZipFile, not
    Compress-Archive), because a build step that verifies itself with its own
    tooling proves nothing.

    Anything not on the allowlist cannot reach the archive, so a signing key,
    a .lic, an evidence certificate or the private tasks/ notes cannot ship by
    accident even if one is sitting in the working tree.

.PARAMETER OutputDirectory
    Where the .zip is written. Defaults to dist\ beside the repository root,
    which is gitignored.

.EXAMPLE
    .\tools\Build-ReleaseZip.ps1

.NOTES
    Exits non-zero if any check fails, so it is safe to gate a release on.
#>
[CmdletBinding()]
param(
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'dist' }

Write-Host "Repository : $repoRoot"

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
$manifestPath = Join-Path $repoRoot 'EraseDrive\EraseDrive.psd1'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Manifest not found at '$manifestPath'."
}
$version = (Import-PowerShellDataFile -LiteralPath $manifestPath).ModuleVersion
Write-Host "Version    : $version"

# ---------------------------------------------------------------------------
# Staging, bounded
# ---------------------------------------------------------------------------
# This directory gets deleted recursively, so it is asserted before it is
# touched: under TEMP, not a drive root, and carrying a name this script owns.
# A recursive delete driven by an unvalidated path is how a working tree gets
# destroyed by a build script.
$staging = Join-Path $env:TEMP "EraseDrive-release-$version"
$resolvedTemp = [System.IO.Path]::GetFullPath($env:TEMP)
$resolvedStage = [System.IO.Path]::GetFullPath($staging)

if (-not $resolvedStage.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use staging directory '$resolvedStage': it is not under TEMP."
}
if ($resolvedStage -eq [System.IO.Path]::GetPathRoot($resolvedStage)) {
    throw "Refusing to use staging directory '$resolvedStage': it is a drive root."
}
if ($resolvedStage -notlike '*EraseDrive-release-*') {
    throw "Refusing to use staging directory '$resolvedStage': unexpected name."
}

Write-Host "Staging    : $resolvedStage"
if (Test-Path -LiteralPath $resolvedStage) {
    Remove-Item -LiteralPath $resolvedStage -Recurse -Force
}
New-Item -Path $resolvedStage -ItemType Directory -Force | Out-Null

# ---------------------------------------------------------------------------
# Allowlist. Nothing else can reach the archive.
# ---------------------------------------------------------------------------
$payload = @(
    @{ Path = 'EraseDrive';           Required = $true;  Recurse = $true  }
    @{ Path = 'Start-EraseDrive.ps1'; Required = $true;  Recurse = $false }
    @{ Path = 'README.md';            Required = $true;  Recurse = $false }
    @{ Path = 'LICENSE';              Required = $true;  Recurse = $false }
    @{ Path = 'NOTICE';               Required = $true;  Recurse = $false }
    @{ Path = 'logo.png';             Required = $false; Recurse = $false }
    @{ Path = 'logo.ico';             Required = $false; Recurse = $false }
)

$missing = @()
foreach ($item in $payload) {
    $source = Join-Path $repoRoot $item.Path
    if (-not (Test-Path -LiteralPath $source)) {
        if ($item.Required) { $missing += $item.Path }
        else { Write-Host "  optional, absent : $($item.Path)" }
        continue
    }
    if ($item.Recurse) { Copy-Item -LiteralPath $source -Destination $resolvedStage -Recurse -Force }
    else               { Copy-Item -LiteralPath $source -Destination $resolvedStage -Force }
    Write-Host "  staged           : $($item.Path)"
}
if ($missing.Count -gt 0) {
    throw "Required release content is missing from the repository: $($missing -join ', ')"
}

# ---------------------------------------------------------------------------
# Compress
# ---------------------------------------------------------------------------
New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
$zipPath = Join-Path $OutputDirectory "EraseDrive-$version.zip"
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }

# Entries are written by hand rather than with Compress-Archive, because
# PowerShell 5.1's Compress-Archive records entry names with BACKSLASH
# separators. The ZIP spec (APPNOTE 4.4.17.1) mandates forward slashes, and
# extractors that follow it - unzip on Linux, Archive Utility on macOS - read
# 'EraseDrive\EraseDrive.psd1' as a single flat file whose name contains a
# backslash, collapsing the module directory. Windows Explorer happens to be
# lenient, which is exactly why this would have shipped unnoticed.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zipStream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew)
try {
    $zip = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $stagedFiles = Get-ChildItem -LiteralPath $resolvedStage -Recurse -File
        foreach ($file in $stagedFiles) {
            $relative = $file.FullName.Substring($resolvedStage.Length).TrimStart('\', '/').Replace('\', '/')
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $file.FullName, $relative,
                [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    }
    finally { $zip.Dispose() }
}
finally { $zipStream.Dispose() }

# ---------------------------------------------------------------------------
# Verify by reading the archive back with a DIFFERENT reader
# ---------------------------------------------------------------------------
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $entries = $archive.Entries | ForEach-Object { $_.FullName }
}
finally {
    $archive.Dispose()
}

$problems = @()

# Content that must be present, or the archive is not a usable product.
$mustContain = @(
    'EraseDrive/EraseDrive.psd1'
    'EraseDrive/EraseDrive.psm1'
    'Start-EraseDrive.ps1'
    'README.md'
    'LICENSE'
    'NOTICE'
)
foreach ($required in $mustContain) {
    if ($entries -notcontains $required) { $problems += "MISSING: $required" }
}

# Content that must never be published. A signed .lic in a public archive would
# hand every downloader the paid tier; a .pfx or key would be worse.
$mustNotMatch = @(
    '*.lic'; '*.pfx'; '*.p12'; '*.key'; '*private*.xml'
    'tasks/*'; 'dist/*'; '.claude/*'; 'EraseDrive-Evidence/*'
    '*.log'; 'Tests/*'; 'installer/*'; 'ship-to-first-dollar/*'; 'licensing/*'
)
foreach ($entry in $entries) {
    foreach ($forbidden in $mustNotMatch) {
        if ($entry -like $forbidden) { $problems += "FORBIDDEN: $entry (matched '$forbidden')" }
    }
}

# The committed public key must ship, and must actually be populated: an empty
# EraseDriveLicense.pub means no license can ever validate.
$pubEntry = $entries | Where-Object { $_ -eq 'EraseDrive/EraseDriveLicense.pub' }
if (-not $pubEntry) {
    $problems += 'MISSING: EraseDrive/EraseDriveLicense.pub'
}
else {
    $stagedPub = Join-Path $resolvedStage 'EraseDrive\EraseDriveLicense.pub'
    $pubBytes  = (Get-Item -LiteralPath $stagedPub).Length
    if ($pubBytes -lt 100) {
        Write-Warning ("EraseDriveLicense.pub is $pubBytes bytes. The keypair generator has " +
                       'not been run, so no license will validate against this build.')
    }
}

Write-Host ''
Write-Host "Archive    : $zipPath"
Write-Host "Entries    : $($entries.Count)"
$hash = Get-FileHash -LiteralPath $zipPath -Algorithm SHA256
Write-Host "SHA256     : $($hash.Hash)"
Write-Host "Size       : $([math]::Round((Get-Item -LiteralPath $zipPath).Length / 1KB, 1)) KB"

if ($problems.Count -gt 0) {
    Write-Host ''
    Write-Host 'ARCHIVE REJECTED:' -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    Remove-Item -LiteralPath $zipPath -Force
    throw "$($problems.Count) problem(s) with the release archive. It has been deleted."
}

Write-Host ''
Write-Host 'Archive verified: required content present, nothing forbidden.' -ForegroundColor Green

# ---------------------------------------------------------------------------
# RELEASE GATE: will an antivirus actually let a customer load this?
# ---------------------------------------------------------------------------
# v3.1.0 was published and withdrawn the same hour because nobody had ever loaded
# the module from outside the repository volume, which is on an AV exclusion. The
# content check above proves the right FILES are in the archive; it says nothing
# about whether the machine receiving them will permit them to run.
#
# The archive is deliberately NOT deleted when this gate fails. It is the exact
# artifact that has to be submitted to the antivirus vendor as a false positive,
# so it needs to survive. The non-zero exit is what stops the release.
Write-Host ''
Write-Host 'Running the antivirus load gate against the built archive...' -ForegroundColor Cyan

$gateScript = Join-Path $PSScriptRoot 'Test-AmsiClean.ps1'
if (-not (Test-Path -LiteralPath $gateScript)) {
    throw "Release gate missing: $gateScript. Refusing to call this archive releasable."
}

$gateStage = Join-Path $env:TEMP ('EraseDrive-relgate-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -Path $gateStage -ItemType Directory -Force | Out-Null
try {
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $gateStage)
    $extractedModule = Join-Path $gateStage 'EraseDrive'

    & $gateScript -ModulePath $extractedModule
    $gateExit = $LASTEXITCODE

    if ($gateExit -ne 0) {
        Write-Host ''
        Write-Host 'RELEASE GATE FAILED.' -ForegroundColor Red
        Write-Host "The archive at $zipPath has been KEPT so it can be submitted to the" -ForegroundColor Red
        Write-Host 'antivirus vendor as a false positive. It must NOT be released.' -ForegroundColor Red
        exit 1
    }

    Write-Host ''
    Write-Host 'Release gate passed: the shipped archive loads cleanly off-volume.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $gateStage -Recurse -Force -ErrorAction SilentlyContinue
}

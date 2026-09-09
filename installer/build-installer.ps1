#Requires -Version 5.1

<#
.SYNOPSIS
    Builds and (optionally) Authenticode-signs the EraseDrive Inno Setup installer.

.DESCRIPTION
    Wraps the Inno Setup compiler (ISCC.exe) and Windows signtool.exe. Produces a
    distributable .exe under <repo-root>\dist\.

    Signing: when a code-signing PFX is configured (via -PfxPath or the
    ERASEDRIVE_SIGNING_PFX env var), this script runs signtool against the produced
    installer with SHA-256 file digest and an RFC-3161 timestamp.

    Until the Sectigo OV cert is procured, run with -SkipSign or simply omit the PFX env
    vars. The installer will be unsigned and SmartScreen will block IT-admin downloads -
    that is intentional: do not publish unsigned installers per the project plan.

.PARAMETER IsccPath
    Path to ISCC.exe. Default: 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'.

.PARAMETER IssScript
    Path to the .iss script. Default: <this-script-dir>\EraseDrive.iss.

.PARAMETER OutputDir
    Directory where Inno Setup writes the .exe. Must match the OutputDir in the .iss.
    Default: <repo-root>\dist.

.PARAMETER PfxPath
    Code-signing certificate (.pfx). Default: env:ERASEDRIVE_SIGNING_PFX.

.PARAMETER PfxPassword
    PFX password. Default: env:ERASEDRIVE_SIGNING_PFX_PASSWORD. (Plaintext; rely on env-var
    sourcing rather than passing on the command line.)

.PARAMETER TimestampUrl
    RFC-3161 timestamp URL. Default: http://timestamp.sectigo.com.

.PARAMETER SkipSign
    Skip the signtool step even if a PFX is configured. Useful for local smoke tests.

.EXAMPLE
    # Unsigned build (pre-procurement)
    .\build-installer.ps1 -SkipSign

.EXAMPLE
    # Signed build with env vars set
    $env:ERASEDRIVE_SIGNING_PFX = 'C:\Users\me\Secrets\EraseDrive\sectigo-ov.pfx'
    $env:ERASEDRIVE_SIGNING_PFX_PASSWORD = '...'
    .\build-installer.ps1
#>
[CmdletBinding()]
param(
    [string]$IsccPath = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    [string]$IssScript,
    [string]$OutputDir,
    [string]$PfxPath = $env:ERASEDRIVE_SIGNING_PFX,
    [string]$PfxPassword = $env:ERASEDRIVE_SIGNING_PFX_PASSWORD,
    [string]$TimestampUrl = 'http://timestamp.sectigo.com',
    [switch]$SkipSign
)

$ErrorActionPreference = 'Stop'

if (-not $IssScript) {
    $IssScript = Join-Path $PSScriptRoot 'EraseDrive.iss'
}
if (-not $OutputDir) {
    $OutputDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'dist'
}

if (-not (Test-Path -LiteralPath $IsccPath)) {
    throw "Inno Setup compiler not found at '$IsccPath'. Install Inno Setup 6 from https://jrsoftware.org/isdl.php or pass -IsccPath."
}

if (-not (Test-Path -LiteralPath $IssScript)) {
    throw "Inno Setup script not found at '$IssScript'."
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

Write-Host "Compiling installer..." -ForegroundColor Cyan
Write-Host "  Script: $IssScript" -ForegroundColor DarkGray
Write-Host "  Output: $OutputDir" -ForegroundColor DarkGray

& $IsccPath $IssScript
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compilation failed (exit code $LASTEXITCODE)."
}

$installer = Get-ChildItem -LiteralPath $OutputDir -Filter 'EraseDrive-Setup-*.exe' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $installer) {
    throw "Could not locate the produced installer .exe in '$OutputDir'."
}

Write-Host "Installer built: $($installer.FullName)" -ForegroundColor Green
Write-Host "  Size: $([Math]::Round($installer.Length / 1MB, 2)) MB" -ForegroundColor DarkGray

if ($SkipSign) {
    Write-Warning "Signing skipped by -SkipSign. The installer is UNSIGNED; do not distribute to public IT-admin audiences."
    return
}

if (-not $PfxPath) {
    Write-Warning "No code-signing PFX configured. Set ERASEDRIVE_SIGNING_PFX or pass -PfxPath. The installer is UNSIGNED."
    return
}

if (-not (Test-Path -LiteralPath $PfxPath)) {
    Write-Warning "PFX file not found at '$PfxPath'. The installer is UNSIGNED."
    return
}

# Locate signtool.exe
$signtool = $null
$cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($cmd) { $signtool = $cmd.Source }

if (-not $signtool) {
    $candidatePaths = @()
    $kitsRoot = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kitsRoot) {
        $candidatePaths += Get-ChildItem -LiteralPath $kitsRoot -Directory |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' }
    }
    foreach ($c in $candidatePaths) {
        if (Test-Path -LiteralPath $c) { $signtool = $c; break }
    }
}

if (-not $signtool) {
    Write-Warning "signtool.exe not found. Install the Windows 10/11 SDK and re-run, or pre-add signtool to PATH. The installer is UNSIGNED."
    return
}

Write-Host "Signing installer with $signtool..." -ForegroundColor Cyan

$signArgs = @('sign', '/f', $PfxPath)
if ($PfxPassword) { $signArgs += @('/p', $PfxPassword) }
$signArgs += @(
    '/fd', 'SHA256',
    '/td', 'SHA256',
    '/tr', $TimestampUrl,
    '/d',  'EraseDrive Forensic Disk Wiper',
    '/du', 'https://erasedrive.io',
    $installer.FullName
)

& $signtool @signArgs
if ($LASTEXITCODE -ne 0) {
    throw "signtool sign failed (exit code $LASTEXITCODE)."
}

& $signtool 'verify' '/pa' '/v' $installer.FullName
if ($LASTEXITCODE -ne 0) {
    throw "signtool verify failed (exit code $LASTEXITCODE)."
}

Write-Host "Installer signed and verified: $($installer.FullName)" -ForegroundColor Green

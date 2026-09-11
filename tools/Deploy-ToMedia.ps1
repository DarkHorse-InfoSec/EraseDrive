<#
.SYNOPSIS
    Refresh a removable stick with the current EraseDrive module and field tools.

.DESCRIPTION
    Follows the fleet rules for bulk filesystem work: a script rather than inline
    commands, an explicit allowlist of what gets copied, the destination asserted
    to be a real removable volume and never a drive root it was not told about,
    failures counted rather than swallowed, and verification afterwards by
    re-reading the destination rather than trusting the copy.

    It never deletes anything at the destination except the module folder it is
    replacing, and it leaves the evidence folder alone.

.PARAMETER DriveLetter
    Target drive letter, e.g. E.

.PARAMETER Force
    Proceed even if the target is a fixed disk. Off by default, because the whole
    point is that this goes onto removable media.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z]$')]
    [string] $DriveLetter,

    [switch] $Force
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$dest = "${DriveLetter}:\"

Write-Host ''
Write-Host ("Source : {0}" -f $repo)
Write-Host ("Target : {0}" -f $dest)

# --- Bound the target. ----------------------------------------------------
if (-not (Test-Path -LiteralPath $dest)) { throw "Drive $dest is not present." }

$vol = Get-Volume -DriveLetter $DriveLetter -ErrorAction Stop
Write-Host ("Volume : {0} ({1}, {2:N1} GB, {3:N1} GB free)" -f $vol.FileSystemLabel, $vol.FileSystem, ($vol.Size/1GB), ($vol.SizeRemaining/1GB))

$part = Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
$disk = if ($part) { Get-Disk -Number $part.DiskNumber -ErrorAction SilentlyContinue } else { $null }
if ($disk) {
    Write-Host ("Disk   : {0} (bus {1})" -f $disk.FriendlyName, $disk.BusType)
    if (($disk.IsSystem -or $disk.IsBoot)) {
        throw "REFUSING: $dest is on the system or boot disk. This deploys to removable media."
    }
    if ($disk.BusType -notin @('USB','SD','MMC','1394') -and -not $Force) {
        throw "REFUSING: $dest is on a $($disk.BusType) disk, not removable media. Pass -Force only if you are certain."
    }
}

# --- Explicit allowlist. Nothing is copied that is not named here. ---------
$moduleSrc = Join-Path $repo 'EraseDrive'
$items = @(
    @{ Src = Join-Path $repo 'Start-EraseDrive.ps1';                    Dst = 'Start-EraseDrive.ps1' }
    @{ Src = Join-Path $repo 'LICENSE';                                 Dst = 'LICENSE' }
    @{ Src = Join-Path $repo 'NOTICE';                                  Dst = 'NOTICE' }
    @{ Src = Join-Path $repo 'deploy\READ-ME-FIRST.md';                 Dst = 'READ-ME-FIRST.md' }
    @{ Src = Join-Path $repo 'tools\Test-EraseDriveReadiness.ps1';      Dst = 'tools\Test-EraseDriveReadiness.ps1' }
    @{ Src = Join-Path $repo 'tools\Invoke-ReissueDryRun.ps1';          Dst = 'tools\Invoke-ReissueDryRun.ps1' }
)

$failures = 0
$copied   = 0

# Module folder: replace wholesale so a removed file does not linger.
Write-Host ''
Write-Host 'Copying module...'
$moduleDst = Join-Path $dest 'EraseDrive'
try {
    if (Test-Path -LiteralPath $moduleDst) { Remove-Item -LiteralPath $moduleDst -Recurse -Force }
    Copy-Item -LiteralPath $moduleSrc -Destination $moduleDst -Recurse -Force
    $copied++
}
catch { Write-Host ("  FAILED module copy: {0}" -f $_.Exception.Message) -ForegroundColor Red; $failures++ }

foreach ($i in $items) {
    $target = Join-Path $dest $i.Dst
    try {
        if (-not (Test-Path -LiteralPath $i.Src)) { throw "source missing: $($i.Src)" }
        $parent = Split-Path -Parent $target
        if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
        Copy-Item -LiteralPath $i.Src -Destination $target -Force
        Write-Host ("  copied  {0}" -f $i.Dst)
        $copied++
    }
    catch {
        Write-Host ("  FAILED  {0}: {1}" -f $i.Dst, $_.Exception.Message) -ForegroundColor Red
        $failures++
    }
}

# Evidence folder, left alone if it already exists.
$evidence = Join-Path $dest 'EraseDrive-Evidence'
if (-not (Test-Path -LiteralPath $evidence)) { New-Item -Path $evidence -ItemType Directory -Force | Out-Null }

# --- Verify by re-reading the destination, not by trusting the copy. -------
Write-Host ''
Write-Host 'Verifying...'
$problems = @()

$mustExist = @(
    'EraseDrive\EraseDrive.psd1'
    'EraseDrive\EraseDrive.psm1'
    'EraseDrive\Private\Test-EraseVerification.ps1'
    'EraseDrive\Public\Invoke-DeviceReissueWipe.ps1'
    'Start-EraseDrive.ps1'
    'READ-ME-FIRST.md'
    'tools\Test-EraseDriveReadiness.ps1'
    'tools\Invoke-ReissueDryRun.ps1'
)
foreach ($m in $mustExist) {
    if (-not (Test-Path -LiteralPath (Join-Path $dest $m))) { $problems += "MISSING: $m" }
}

# Nothing secret may travel.
$forbidden = Get-ChildItem -LiteralPath $dest -Recurse -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -in @('.pfx','.lic','.snk') -or $_.Name -like '*private*' }
foreach ($f in $forbidden) { $problems += "FORBIDDEN ON MEDIA: $($f.FullName)" }

# The dormant function must still be dormant.
$manifest = Import-PowerShellDataFile -Path (Join-Path $dest 'EraseDrive\EraseDrive.psd1')
foreach ($fn in @('Invoke-DeviceReissueWipe','New-EraseDriveBootMedia')) {
    if ($manifest.FunctionsToExport -contains $fn) { $problems += "SAFETY: $fn is EXPORTED on the media. It must ship dormant." }
}
Write-Host ("  exported functions: {0}" -f ($manifest.FunctionsToExport -join ', '))

Write-Host ''
Write-Host '--------------------------------------------------------------'
Write-Host ("Items copied : {0}" -f $copied)
Write-Host ("Failures     : {0}" -f $failures) -ForegroundColor $(if ($failures) {'Red'} else {'Green'})
Write-Host ("Problems     : {0}" -f $problems.Count) -ForegroundColor $(if ($problems.Count) {'Red'} else {'Green'})
foreach ($p in $problems) { Write-Host ("  {0}" -f $p) -ForegroundColor Red }
Write-Host '--------------------------------------------------------------'

if ($failures -gt 0 -or $problems.Count -gt 0) {
    Write-Host 'DEPLOY FAILED. Do not take this media into the field.' -ForegroundColor Red
    exit 1
}
Write-Host 'Deploy verified.' -ForegroundColor Green
exit 0

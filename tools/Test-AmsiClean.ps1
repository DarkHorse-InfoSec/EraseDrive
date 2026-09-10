<#
.SYNOPSIS
    RELEASE GATE. Proves the module can actually be loaded on a machine that is
    scanning it, from a location a customer would extract it to.

.DESCRIPTION
    This exists because v3.1.0 was published and had to be withdrawn the same
    hour. Every one of the 282 tests passed, and every one of them ran from the
    repository on D:, which sits on an antivirus exclusion. The first time the
    module was ever loaded from C: was after publishing, and it failed
    immediately:

        Test-EraseVerification.ps1:1 char:1
        This script contains malicious content and has been blocked by your
        antivirus software.

    An exclusion path is an untested configuration that looks exactly like a
    tested one. A disk wiper is going to be inspected by every endpoint product
    on the market, so "does the AV let this load" is a product requirement, not
    an environment quirk, and it needs a gate rather than a note.

    WHAT THIS CHECKS
    Each .ps1 is copied to a staging directory OUTSIDE the repository volume and
    dot-sourced there. Dot-sourcing forces a full parse, which is what the AMSI
    scan hooks, and it is what actually failed. It defines functions; it does not
    invoke any of them, so nothing here touches a disk.

    WHY NOT JUST IMPORT THE MODULE
    Importing needs elevation, because EraseDrive.psm1 carries
    '#requires -RunAsAdministrator'. The AMSI verdict lands at parse time, before
    that check, so per-file dot-sourcing catches the same failure and runs
    unelevated. The gate therefore has no excuse not to be run. If the session IS
    elevated, the full import is attempted as well.

.PARAMETER StagingRoot
    Where to stage. MUST NOT be on the same volume as the repository, because
    that volume is the one likely to be excluded. Defaults to the user TEMP
    directory.

.PARAMETER ModulePath
    The module to check. Defaults to the repository's EraseDrive directory. Point
    it at an extracted release ZIP to check exactly what ships.

.EXAMPLE
    .\tools\Test-AmsiClean.ps1
    Checks the working-tree module.

.EXAMPLE
    .\tools\Test-AmsiClean.ps1 -ModulePath C:\Temp\ED-smoke\EraseDrive
    Checks an extracted release archive, which is what a customer actually gets.

.OUTPUTS
    Exit code 0 when every file parsed. Non-zero when anything was blocked or
    failed to parse. Intended to gate a release.
#>
[CmdletBinding()]
param(
    [string] $ModulePath,
    [string] $StagingRoot = $env:TEMP
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $ModulePath) { $ModulePath = Join-Path $repoRoot 'EraseDrive' }

if (-not (Test-Path -LiteralPath $ModulePath)) {
    Write-Host "Module path not found: $ModulePath" -ForegroundColor Red
    exit 2
}

# ---------------------------------------------------------------------------
# The staging location is the whole point. Refuse to run somewhere useless.
# ---------------------------------------------------------------------------
# The blind spot this gate exists to close is that the REPOSITORY volume is on an
# antivirus exclusion, so anything parsed there passes regardless of what a
# scanner would say. Staging must therefore be off the repository volume.
#
# Note this is compared against the REPO, not against -ModulePath. The module
# under test is frequently an archive already extracted into TEMP, and that is a
# perfectly good thing to test: it is the customer's actual install location. An
# earlier version of this check compared against $ModulePath and refused to run
# in exactly that, the most realistic, case.
$repoQualifier    = (Split-Path -Qualifier (Resolve-Path -LiteralPath $repoRoot).Path)
$stagingQualifier = (Split-Path -Qualifier (Resolve-Path -LiteralPath $StagingRoot).Path)

Write-Host "Module    : $ModulePath"
Write-Host "Staging   : $StagingRoot"
Write-Host "Repo vol  : $repoQualifier  (excluded from scanning on this machine)"

if ($repoQualifier -eq $stagingQualifier) {
    Write-Host ''
    Write-Host "REFUSING TO RUN: staging root is on the repository volume ($stagingQualifier)." -ForegroundColor Red
    Write-Host 'That volume is the one likely to be on an antivirus exclusion, so a pass there' -ForegroundColor Red
    Write-Host 'would prove nothing. Pass -StagingRoot pointing at a different volume.' -ForegroundColor Red
    exit 3
}

$staging = Join-Path $StagingRoot ("EraseDrive-amsi-gate-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -Path $staging -ItemType Directory -Force | Out-Null

$blocked = New-Object System.Collections.ArrayList
$failed  = New-Object System.Collections.ArrayList
$checked = 0

try {
    $files = Get-ChildItem -LiteralPath $ModulePath -Recurse -Filter '*.ps1' | Sort-Object FullName

    if ($files.Count -eq 0) {
        Write-Host "No .ps1 files found under $ModulePath - nothing was checked." -ForegroundColor Red
        exit 2
    }

    foreach ($f in $files) {
        $dest = Join-Path $staging $f.Name
        Copy-Item -LiteralPath $f.FullName -Destination $dest -Force

        # A child process per file, so one blocked file cannot abort the sweep and
        # hide the ones after it. Dot-sourcing defines; it does not execute.
        # A blocked file makes the child write to stderr, which under
        # ErrorActionPreference='Stop' would terminate this sweep at the FIRST
        # blocked file and hide every one after it. The gate has to report all of
        # them, so native stderr is demoted to output for this call only.
        $output = & {
            $ErrorActionPreference = 'Continue'
            & powershell.exe -NoProfile -NonInteractive -Command ". '$dest'" 2>&1 | Out-String
        }
        $checked++

        if ($output -match 'malicious content|blocked by your antivirus') {
            [void] $blocked.Add($f.FullName)
            Write-Host ("  BLOCKED  {0}" -f $f.Name) -ForegroundColor Red
        }
        elseif ($output -match 'ParserError|ParseException') {
            [void] $failed.Add(($f.FullName + ' :: ' + ($output.Trim() -split "`n")[0]))
            Write-Host ("  PARSEERR {0}" -f $f.Name) -ForegroundColor Yellow
        }
        else {
            Write-Verbose ("  ok       {0}" -f $f.Name)
        }

        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
    }

    # If elevated, also prove the real thing: a full module import from staging.
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $importResult = 'SKIPPED (not elevated; per-file parse above is the AMSI-relevant check)'
    if ($isAdmin) {
        $importStage = Join-Path $staging 'EraseDrive'
        Copy-Item -LiteralPath $ModulePath -Destination $importStage -Recurse -Force
        $out = & {
            $ErrorActionPreference = 'Continue'
            & powershell.exe -NoProfile -NonInteractive -Command "Import-Module '$importStage' -Force; if (Get-Module EraseDrive) { 'IMPORT-OK' }" 2>&1 | Out-String
        }
        if ($out -match 'IMPORT-OK') { $importResult = 'PASS' }
        else { $importResult = 'FAIL :: ' + (($out.Trim() -split "`n") | Select-Object -First 2) -join ' | ' }
    }

    Write-Host ''
    Write-Host '--------------------------------------------------------------'
    Write-Host ("Files parsed off-volume : {0}" -f $checked)
    Write-Host ("Blocked by antivirus    : {0}" -f $blocked.Count)
    Write-Host ("Other parse failures    : {0}" -f $failed.Count)
    Write-Host ("Full module import      : {0}" -f $importResult)
    Write-Host '--------------------------------------------------------------'

    foreach ($b in $blocked) { Write-Host "BLOCKED: $b" -ForegroundColor Red }
    foreach ($x in $failed)  { Write-Host "FAILED : $x" -ForegroundColor Yellow }

    if ($blocked.Count -gt 0 -or $failed.Count -gt 0 -or $importResult -like 'FAIL*') {
        Write-Host ''
        Write-Host 'GATE FAILED. This must not be released.' -ForegroundColor Red
        exit 1
    }

    Write-Host ''
    Write-Host 'GATE PASSED: every file parsed off-volume without an antivirus verdict.' -ForegroundColor Green
    exit 0
}
finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}

<#
.SYNOPSIS
    READ-ONLY preflight. Answers "will EraseDrive actually work on THIS machine,
    and which operations are safe here?" before anyone tries it on a real device.

.DESCRIPTION
    Run this FIRST on any target machine, especially a domain-joined or managed
    one. It changes nothing, touches no disk, and needs no elevation to run,
    though it will tell you where elevation is required.

    It exists because the failure modes on a managed device are environmental and
    they surface late: the antivirus refuses the module at import, Group Policy
    enforces AllSigned, WDAC drops PowerShell into ConstrainedLanguage, or the
    operator is not a local administrator. Finding any of those out halfway
    through a wipe is the worst possible time.

    WHAT IT DELIBERATELY DOES NOT DO
    It does not erase, does not write, does not modify configuration, and does not
    load the module's destructive functions. It reports.

.PARAMETER ModulePath
    Module to test importing. Defaults to the EraseDrive folder beside this script.

.EXAMPLE
    .\Test-EraseDriveReadiness.ps1

.OUTPUTS
    A readiness report and a per-operation verdict. Exit code 0 if at least the
    secondary-disk erase path is usable, 1 if nothing is.
#>
[CmdletBinding()]
param(
    [string] $ModulePath
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Make this script robust to the environment it is diagnosing.
# ---------------------------------------------------------------------------
# If PowerShell 7's module directories are inherited from a parent process, they
# shadow Windows PowerShell's own, and 5.1 silently loses providers and cmdlets
# from Microsoft.PowerShell.Security, including Get-ExecutionPolicy and the Cert:
# drive. A readiness check that dies because of the condition it is meant to
# report is no use, so rebuild the path from the registry, and REPORT that this
# was necessary, because it will bite anything else run from the same shell.
$script:PathWasPolluted = $false
$inherited = $env:PSModulePath
$fromRegistry = ([Environment]::GetEnvironmentVariable('PSModulePath','User') + ';' +
                 [Environment]::GetEnvironmentVariable('PSModulePath','Machine')).Trim(';')
if ($fromRegistry -and $inherited -ne $fromRegistry) {
    $env:PSModulePath = $fromRegistry
    $script:PathWasPolluted = $true
}
Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue
Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue

if (-not $ModulePath) {
    $ModulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'EraseDrive'
}

function Write-Check {
    param([string] $Label, [string] $Value, [ValidateSet('ok','warn','bad','info')][string] $State = 'info')
    $colour = switch ($State) { 'ok' {'Green'} 'warn' {'Yellow'} 'bad' {'Red'} default {'Gray'} }
    $mark   = switch ($State) { 'ok' {'[ OK ]'} 'warn' {'[WARN]'} 'bad' {'[FAIL]'} default {'[ -- ]'} }
    Write-Host ("{0} {1,-34}{2}" -f $mark, $Label, $Value) -ForegroundColor $colour
}

$blockers = New-Object System.Collections.ArrayList
$warnings = New-Object System.Collections.ArrayList

Write-Host ''
Write-Host '=============================================================='
Write-Host ' EraseDrive readiness check (read-only, changes nothing)'
Write-Host '=============================================================='
Write-Host ("Machine : {0}    Date: {1}" -f $env:COMPUTERNAME, (Get-Date))
Write-Host ''

# --- Host -----------------------------------------------------------------
Write-Host '-- Host ------------------------------------------------------'
$psv = $PSVersionTable.PSVersion
Write-Check 'PowerShell version' "$psv ($($PSVersionTable.PSEdition))" $(if ($psv.Major -eq 5) {'ok'} else {'warn'})
if ($psv.Major -ne 5) {
    [void] $warnings.Add("Running PowerShell $psv. The module manifest targets Windows PowerShell 5.1; the GUI in particular expects it.")
}

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
Write-Check 'Operating system' $(if ($os) { "$($os.Caption) $($os.Version)" } else { 'unknown' }) 'info'

Write-Check 'PSModulePath inherited clean' $(if ($script:PathWasPolluted) {'NO - rebuilt from registry'} else {'yes'}) $(if ($script:PathWasPolluted) {'warn'} else {'ok'})
if ($script:PathWasPolluted) {
    [void] $warnings.Add("PSModulePath was inherited polluted from the parent process, most often PowerShell 7's module directories shadowing Windows PowerShell's. This script repaired its own copy, but ANY OTHER PowerShell 5.1 session started from the same parent will silently lose cmdlets such as Get-ExecutionPolicy and Import-PowerShellDataFile. Start EraseDrive from a fresh Windows PowerShell 5.1 window, not from an editor or agent terminal.")
}

# --- Elevation ------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Check 'Running elevated' $(if ($isAdmin) {'yes'} else {'NO'}) $(if ($isAdmin) {'ok'} else {'bad'})
if (-not $isAdmin) {
    [void] $blockers.Add("Not elevated. EraseDrive.psm1 carries '#Requires -RunAsAdministrator' and will not import. Re-run this from an elevated Windows PowerShell 5.1 prompt.")
}

# --- Language mode: the one that fails late and confusingly ---------------
$lang = $ExecutionContext.SessionState.LanguageMode
Write-Check 'PowerShell language mode' $lang $(if ($lang -eq 'FullLanguage') {'ok'} else {'bad'})
if ($lang -ne 'FullLanguage') {
    [void] $blockers.Add("Language mode is '$lang', not FullLanguage. WDAC or AppLocker is enforcing. Add-Type and direct .NET calls are blocked, so hardware detection and erase verification cannot run. Use the WinPE boot media, or have the module allowed in the device's application control policy.")
}

# --- Execution policy, including who set it -------------------------------
Write-Host ''
Write-Host '-- Script execution ------------------------------------------'
$effective = $null
try { $effective = Get-ExecutionPolicy -ErrorAction Stop } catch { }
if (-not $effective) {
    Write-Check 'Effective execution policy' 'COULD NOT BE READ' 'warn'
    [void] $warnings.Add("Get-ExecutionPolicy is unavailable in this shell, so the execution policy was NOT checked. Treat it as unknown rather than fine.")
}
else {
    Write-Check 'Effective execution policy' $effective $(if ($effective -in @('Restricted','AllSigned')) {'bad'} else {'ok'})
}
foreach ($scope in 'MachinePolicy','UserPolicy','Process','CurrentUser','LocalMachine') {
    $p = Get-ExecutionPolicy -Scope $scope -ErrorAction SilentlyContinue
    if ($p -and $p -ne 'Undefined') { Write-Check "  scope: $scope" $p 'info' }
}
if ($effective -eq 'AllSigned') {
    [void] $blockers.Add("Execution policy is AllSigned. EraseDrive is NOT code-signed yet, so nothing will run. This is set by Group Policy on most managed estates and cannot be overridden locally.")
}
elseif ($effective -eq 'Restricted') {
    [void] $blockers.Add("Execution policy is Restricted. No scripts run at all.")
}
$gpoPolicy = Get-ExecutionPolicy -Scope MachinePolicy -ErrorAction SilentlyContinue
if ($gpoPolicy -and $gpoPolicy -ne 'Undefined') {
    [void] $warnings.Add("Execution policy is set by Group Policy (MachinePolicy = $gpoPolicy) and cannot be changed locally.")
}

# --- Antivirus: the thing that actually blocked the v3.1.0 release --------
Write-Host ''
Write-Host '-- Antivirus -------------------------------------------------'
$activeAv = @()
try {
    Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
        $realtime = ((([int]$_.productState -shr 12) -band 0xF) -ne 0)
        if ($realtime) { $activeAv += $_.displayName }
        Write-Check "  $($_.displayName)" $(if ($realtime) {'ACTIVE (real-time on)'} else {'inactive'}) $(if ($realtime) {'info'} else {'info'})
    }
}
catch { Write-Check '  enumeration' 'failed (needs SecurityCenter2)' 'warn' }
if (-not $activeAv) { Write-Check '  active engine' 'none detected' 'warn' }

# --- Does the module actually import from HERE? --------------------------
Write-Host ''
Write-Host '-- Module import ---------------------------------------------'
Write-Check 'Module path' $ModulePath 'info'
if (-not (Test-Path -LiteralPath $ModulePath)) {
    Write-Check 'Module present' 'NOT FOUND' 'bad'
    [void] $blockers.Add("No module at $ModulePath.")
}
else {
    # Parse every file in a child process. This is what the antivirus hooks, and
    # it is what failed for the withdrawn v3.1.0 release.
    $avBlocked = @()
    foreach ($f in (Get-ChildItem -LiteralPath $ModulePath -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        $out = & {
            $ErrorActionPreference = 'Continue'
            & powershell.exe -NoProfile -NonInteractive -Command ". '$($f.FullName)'" 2>&1 | Out-String
        }
        if ($out -match 'malicious content|blocked by your antivirus') { $avBlocked += $f.Name }
    }
    if ($avBlocked.Count -gt 0) {
        Write-Check 'Antivirus permits the files' ("NO - blocked: " + ($avBlocked -join ', ')) 'bad'
        [void] $blockers.Add("The antivirus on this machine blocks $($avBlocked.Count) module file(s) as malicious: $($avBlocked -join ', '). This is a known false positive. The module cannot import until it is excluded or the vendor corrects the detection.")
    }
    else {
        Write-Check 'Antivirus permits the files' 'yes, all parsed' 'ok'
        # This tested the module WHERE IT ACTUALLY SITS, which is the right thing
        # to test, but the result is only valid for that location. A development
        # machine commonly has the repository volume on an antivirus exclusion,
        # in which case a pass here says nothing about where a customer would
        # extract it. This exact blind spot is why v3.1.0 had to be withdrawn.
        [void] $warnings.Add("The antivirus check passed for the module AT '$ModulePath'. That result applies to that path only. If the module is copied or extracted elsewhere, especially onto a volume that is not on an antivirus exclusion, re-run this check there before relying on it.")
    }

    if ($isAdmin -and $avBlocked.Count -eq 0 -and $lang -eq 'FullLanguage') {
        $imp = & {
            $ErrorActionPreference = 'Continue'
            & powershell.exe -NoProfile -NonInteractive -Command "Import-Module '$ModulePath' -Force; if (Get-Module EraseDrive) { 'IMPORT-OK' }" 2>&1 | Out-String
        }
        if ($imp -match 'IMPORT-OK') { Write-Check 'Full module import' 'PASS' 'ok' }
        else {
            Write-Check 'Full module import' 'FAILED' 'bad'
            [void] $blockers.Add("Import-Module failed: " + (($imp.Trim() -split "`n" | Select-Object -First 1)))
        }
    }
    else {
        Write-Check 'Full module import' 'not attempted (see above)' 'info'
    }
}

# --- Domain and disks -----------------------------------------------------
Write-Host ''
Write-Host '-- Device ----------------------------------------------------'
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$joined = if ($cs) { [bool]$cs.PartOfDomain } else { $null }
Write-Check 'Domain joined' $(if ($joined) { "yes ($($cs.Domain))" } elseif ($null -eq $joined) { 'unknown' } else { 'no' }) 'info'

$adk = Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment'
Write-Check 'Windows ADK + WinPE add-on' $(if ($adk) {'present'} else {'NOT installed'}) $(if ($adk) {'ok'} else {'warn'})
if (-not $adk) { [void] $warnings.Add("The Windows ADK WinPE add-on is not installed, so boot media cannot be built on this machine.") }

Write-Host ''
Write-Host '-- Disks -----------------------------------------------------'
try {
    Get-Disk -ErrorAction Stop | ForEach-Object {
        $role = if ($_.IsSystem -or $_.IsBoot) { 'SYSTEM/BOOT - will be REFUSED' } else { 'secondary - eligible' }
        $state = if ($_.IsSystem -or $_.IsBoot) { 'warn' } else { 'ok' }
        Write-Check ("  disk {0}: {1}" -f $_.Number, $_.FriendlyName) ("{0:N1} GB, {1}, {2}" -f ($_.Size/1GB), $_.BusType, $role) $state
    }
}
catch { Write-Check '  disk enumeration' 'failed' 'warn' }

# --- Verdict --------------------------------------------------------------
Write-Host ''
Write-Host '=============================================================='
Write-Host ' VERDICT'
Write-Host '=============================================================='

if ($blockers.Count -gt 0) {
    Write-Host ''
    Write-Host 'BLOCKERS - nothing will run until these are resolved:' -ForegroundColor Red
    $i = 1
    foreach ($b in $blockers) { Write-Host ("  {0}. {1}" -f $i, $b) -ForegroundColor Red; $i++ }
}
if ($warnings.Count -gt 0) {
    Write-Host ''
    Write-Host 'WARNINGS:' -ForegroundColor Yellow
    $i = 1
    foreach ($w in $warnings) { Write-Host ("  {0}. {1}" -f $i, $w) -ForegroundColor Yellow; $i++ }
}

Write-Host ''
Write-Host 'What each operation can do on this machine:' -ForegroundColor Cyan
$usable = ($blockers.Count -eq 0)

Write-Host ''
Write-Host '  1. Erase a SECONDARY or EXTERNAL disk (Invoke-SecureDiskErase)'
Write-Host ("     {0}" -f $(if ($usable) { 'AVAILABLE. This path is proven on real hardware.' } else { 'BLOCKED by the above.' })) -ForegroundColor $(if ($usable) {'Green'} else {'Red'})

Write-Host ''
Write-Host "  2. Wipe this machine's OWN system disk"
Write-Host '     NOT POSSIBLE, by design. Test-DiskSafeToErase refuses the system and' -ForegroundColor Red
Write-Host '     boot disk, and a tool cannot erase the disk it is running from. This' -ForegroundColor Red
Write-Host '     needs the WinPE boot media, which has NEVER BEEN EXECUTED.' -ForegroundColor Red

Write-Host ''
Write-Host '  3. Wipe USER DATA while keeping Windows (Invoke-ForensicUserDataWipe)'
Write-Host '     EXPORTED AND WILL RUN, BUT IT HAS NEVER BEEN RUN DESTRUCTIVELY.' -ForegroundColor Yellow
Write-Host '     All of its tests mock the parts that destroy. On a domain machine the' -ForegroundColor Yellow
Write-Host "     operator's own profile cannot be removed while signed in, so the result" -ForegroundColor Yellow
Write-Host '     is structurally incomplete and reports itself as such.' -ForegroundColor Yellow
Write-Host '     ALWAYS run it with -WhatIf first. That path is safe and implemented,' -ForegroundColor Yellow
Write-Host '     and it is the only thing that answers "what would this do HERE".' -ForegroundColor Yellow

Write-Host ''
Write-Host '  4. Device reissue wipe / WinPE boot media'
Write-Host '     NOT AVAILABLE. Invoke-DeviceReissueWipe and New-EraseDriveBootMedia' -ForegroundColor Red
Write-Host '     ship dormant and unexported. They have never been executed.' -ForegroundColor Red

Write-Host ''
Write-Host '=============================================================='
if ($usable) { exit 0 } else { exit 1 }

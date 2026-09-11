<#
.SYNOPSIS
    SAFE DRY RUN of the device reissue wipe. Destroys nothing. Cannot be made to
    destroy anything.

.DESCRIPTION
    Invoke-DeviceReissueWipe is the function that removes every user, unjoins the
    domain and runs sysprep /generalize so a device boots to out-of-box setup.
    It is NOT exported in this version, on purpose: it has never been executed
    against a real machine, and a test asserts that it ships dormant.

    This harness lets you find out what it WOULD do on a real domain-joined
    device, without doing any of it. That is genuinely useful information and it
    is the correct first step, but understand what it is: a dry run, not a wipe.

    HOW IT IS PREVENTED FROM DESTROYING ANYTHING

    1. It calls the function with -WhatIf hard-coded. There is no parameter on
       this script that can turn that off, and it accepts no pass-through
       arguments.
    2. $WhatIfPreference is also forced to $true for the whole scope, so any
       nested ShouldProcess call inherits it even if a code path forgot to.
    3. It refuses to run if the target is not domain joined, because the whole
       point is to exercise the domain path.

    WHAT IT STILL WILL NOT TELL YOU
    A dry run exercises the decision logic, not the destruction. It cannot prove
    that profile deletion, the unjoin or sysprep actually succeed. Those remain
    unproven until they run for real on a machine that can be lost.

.PARAMETER EvidencePath
    Where to write the transcript. Defaults to an EraseDrive-Evidence folder
    beside this script, so the record travels with the media rather than staying
    on the machine being examined.

.EXAMPLE
    .\Invoke-ReissueDryRun.ps1

.NOTES
    Run from an ELEVATED Windows PowerShell 5.1 prompt.
#>
[CmdletBinding()]
param(
    [string] $EvidencePath
)

$ErrorActionPreference = 'Stop'

# Belt and braces: nothing in this scope may perform a destructive action.
$WhatIfPreference = $true

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $EvidencePath) {
    $EvidencePath = Join-Path (Split-Path -Parent $here) 'EraseDrive-Evidence'
    if (-not (Test-Path $EvidencePath)) { $EvidencePath = Join-Path $here 'EraseDrive-Evidence' }
}

Write-Host ''
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host ' DEVICE REISSUE WIPE - DRY RUN ONLY' -ForegroundColor Cyan
Write-Host ' Nothing will be deleted, unjoined, or generalized.' -ForegroundColor Cyan
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host ''

# --- Preconditions, replicated here because dot-sourcing bypasses the module's
# --- own #Requires and its language-mode preflight.
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Not elevated. Re-run this from an elevated Windows PowerShell 5.1 prompt."
}
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw ("PowerShell language mode is '$($ExecutionContext.SessionState.LanguageMode)', not FullLanguage. " +
           "WDAC or AppLocker is enforcing on this device and the module cannot run here. " +
           "Run tools\Test-EraseDriveReadiness.ps1 for the full picture.")
}

$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
if (-not $cs -or -not $cs.PartOfDomain) {
    throw ("This device is NOT domain joined" +
           $(if ($cs) { " (domain/workgroup: $($cs.Domain))" } else { '' }) +
           ". The dry run is for exercising the domain path, so there is nothing useful to learn here. " +
           "Run it on the actual target device.")
}

Write-Host ("Device      : {0}" -f $env:COMPUTERNAME)
Write-Host ("Domain      : {0}" -f $cs.Domain)
Write-Host ("Operator    : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-Host ("Evidence to : {0}" -f $EvidencePath)
Write-Host ''

if (-not (Test-Path $EvidencePath)) { New-Item -Path $EvidencePath -ItemType Directory -Force | Out-Null }
$transcript = Join-Path $EvidencePath ("ReissueDryRun_{0}_{1:yyyyMMdd_HHmmss}.txt" -f $env:COMPUTERNAME, (Get-Date))

try { Start-Transcript -Path $transcript -Force | Out-Null } catch { Write-Warning "Transcript unavailable: $($_.Exception.Message)" }

try {
    # The function is deliberately not exported, so dot-source it rather than
    # importing the module. Private functions first: it depends on them.
    $moduleDir = Join-Path (Split-Path -Parent $here) 'EraseDrive'
    if (-not (Test-Path $moduleDir)) { $moduleDir = Join-Path $here 'EraseDrive' }
    if (-not (Test-Path $moduleDir)) { throw "Cannot find the EraseDrive module folder next to this script." }

    $Script:EraseDriveConfig = @{
        LogDirectory  = $EvidencePath
        LogFile       = Join-Path $EvidencePath 'EraseDrive-dryrun.log'
        CertDirectory = $EvidencePath
        LicensePath   = Join-Path $moduleDir 'EraseDrive.lic'
        PublicKeyPath = Join-Path $moduleDir 'EraseDriveLicense.pub'
        MaxLogSizeMB  = 5
        MaxLogFiles   = 3
        Version       = '3.1.0'
    }

    Get-ChildItem (Join-Path $moduleDir 'Private') -Filter '*.ps1' -File | ForEach-Object { . $_.FullName }
    Get-ChildItem (Join-Path $moduleDir 'Public')  -Filter '*.ps1' -File | ForEach-Object { . $_.FullName }

    Write-Host '--- what the reissue wipe WOULD do on this device -------------' -ForegroundColor Yellow
    Write-Host ''

    # -WhatIf is hard-coded. This script exposes no way to remove it.
    Invoke-DeviceReissueWipe -RemoveFromDomain -WipeMethod Standard -WhatIf

    Write-Host ''
    Write-Host '--------------------------------------------------------------' -ForegroundColor Yellow
    Write-Host 'DRY RUN COMPLETE. Nothing was changed on this device.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'What this did and did not establish:' -ForegroundColor Cyan
    Write-Host '  IT DID   : exercise the decision logic. Which profiles it would'
    Write-Host '             target, which it would skip and why, whether it sees'
    Write-Host '             the domain, and where it would write the certificate.'
    Write-Host '  IT DID NOT: prove that profile deletion, the domain unjoin or'
    Write-Host '             sysprep actually succeed. Those have never run.'
    Write-Host ''
    Write-Host ("Transcript: {0}" -f $transcript)
}
finally {
    try { Stop-Transcript | Out-Null } catch { }
}

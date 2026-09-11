#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    EraseDrive - Professional forensic disk and data destruction module.

.DESCRIPTION
    Provides secure data destruction with NIST 800-88 Rev.1 CLEAR via multi-pass
    overwrite, verified by sampling, plus forensic user data wiping and erasure
    certification.

    SSD-aware sanitization capability DETECTION (NVMe Identify Controller, ATA
    IDENTIFY DEVICE) reports whether a given device can reach NIST PURGE and by
    which command. Detection only: this module does not yet ISSUE ATA SANITIZE,
    ATA SECURITY ERASE UNIT, NVMe Format NVM or NVMe Sanitize, so it does not
    perform Purge. Overwriting cannot reach Purge on flash media at all, because
    the FTL keeps over-provisioned, retired and un-erased blocks outside the
    addressable LBA range. Where that distinction matters, the certificate says
    which was achieved and which was merely available.

.NOTES
    Module:  EraseDrive
    Version: 3.1.0
    Author:  DarkHorse InfoSec
#>

# ---------------------------------------------------------------------------
# PREFLIGHT: refuse to load in Constrained Language Mode, and say why.
# ---------------------------------------------------------------------------
# WDAC / AppLocker in enforcement mode drops PowerShell into ConstrainedLanguage,
# which blocks Add-Type outright and blocks .NET method calls on types that are
# not allowlisted. This module needs both: Add-Type with [DllImport] for the
# read-only IOCTL capability detection, [System.IO.FileStream]::new for erase
# verification, and Add-Type for the WinForms GUI.
#
# Without this check the module imports and then fails somewhere in the middle
# with a confusing type error, which for a disk wiper is the worst possible
# moment to discover the environment is locked down. Fail here instead, with the
# cause named and the remedy stated.
#
# FullLanguage is required. Anything else is refused.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    $mode = $ExecutionContext.SessionState.LanguageMode
    throw @"
EraseDrive cannot run in PowerShell language mode '$mode'. FullLanguage is required.

This almost always means WDAC (App Control for Business) or AppLocker is in
enforcement mode on this device, which is common on a domain-joined or otherwise
managed machine.

EraseDrive needs Add-Type and direct .NET calls for hardware capability detection
and for erase verification, and both are blocked in '$mode'. Loading anyway would
fail partway through an operation rather than here.

Options, in order of preference:
  1. Run from the EraseDrive WinPE boot media, which is not subject to the
     device's WDAC or AppLocker policy. This is also the only mode that can
     completely wipe a machine's own system disk.
  2. Have an administrator allow this module in the device's application control
     policy, ideally by publisher once the module is code-signed.
  3. Run on a machine that is not under an enforced application control policy.

Nothing has been changed on this system.
"@
}

# Module-level configuration
$Script:EraseDriveConfig = @{
    LogDirectory    = Join-Path $env:ProgramData 'DarkHorse\EraseDrive'
    LogFile         = Join-Path $env:ProgramData 'DarkHorse\EraseDrive\EraseDrive.log'
    CertDirectory   = Join-Path $env:ProgramData 'DarkHorse\EraseDrive\Certificates'
    LicensePath     = Join-Path $env:ProgramData 'DarkHorse\EraseDrive\license.lic'
    PublicKeyPath   = Join-Path $PSScriptRoot 'EraseDriveLicense.pub'
    MaxLogSizeMB    = 10
    MaxLogFiles     = 5
    Version         = '3.1.0'

    # Where this module was loaded from. Set-EraseDriveEvidenceRoot uses the parent of
    # this path to keep destruction certificates on the operator's USB stick rather than
    # on the machine being wiped and handed over.
    ModuleRoot      = $PSScriptRoot

    # Populated by Set-EraseDriveEvidenceRoot at the start of an operation. Null means
    # the module is still using its ProgramData defaults.
    EvidenceRoot    = $null
}

# Ensure log and certificate directories exist
foreach ($dir in @($Script:EraseDriveConfig.LogDirectory, $Script:EraseDriveConfig.CertDirectory)) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

# Dot-source all private functions
$privatePath = Join-Path $PSScriptRoot 'Private'
if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' -File | ForEach-Object {
        . $_.FullName
    }
}

# Dot-source all public functions
$publicPath = Join-Path $PSScriptRoot 'Public'
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' -File | ForEach-Object {
        . $_.FullName
    }
}

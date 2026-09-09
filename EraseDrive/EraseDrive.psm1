#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    EraseDrive - Professional forensic disk and data destruction module.

.DESCRIPTION
    Provides secure data destruction with NIST 800-88 compliant multi-pass overwrite,
    SSD-aware erasure (ATA Secure Erase / NVMe Format), forensic user data wiping,
    verification passes, and erasure certification.

.NOTES
    Module:  EraseDrive
    Version: 3.1.0
    Author:  DarkHorse InfoSec
#>

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

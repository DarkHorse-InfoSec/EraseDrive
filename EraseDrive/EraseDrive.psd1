@{
    RootModule        = 'EraseDrive.psm1'
    ModuleVersion     = '3.1.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'DarkHorse InfoSec'
    CompanyName       = 'DarkHorse InfoSec'
    Copyright         = '(c) 2026 DarkHorse InfoSec. Licensed under the Apache License, Version 2.0.'
    Description       = 'Professional forensic disk and data destruction tool. NIST SP 800-88 Rev.1 Clear via verified multi-pass overwrite, SSD sanitization-capability detection reporting whether a device can reach Purge, signed PDF Certificate of Destruction (Pro+), and tamper-evident erasure certification.'

    PowerShellVersion = '5.1'
    DotNetFrameworkVersion = '4.5'

    RequiredAssemblies = @(
        'System.Windows.Forms',
        'System.Drawing',
        'Microsoft.VisualBasic'
    )

    FunctionsToExport = @(
        'Invoke-ForensicUserDataWipe',
        'Invoke-SecureDiskErase',
        'Start-EraseDriveGUI'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags       = @('Security', 'Forensics', 'DiskErase', 'DataDestruction', 'NIST800-88')
            ProjectUri = 'https://github.com/HackingPain/EraseDrive'
            LicenseUri = 'https://www.apache.org/licenses/LICENSE-2.0'
        }
    }
}

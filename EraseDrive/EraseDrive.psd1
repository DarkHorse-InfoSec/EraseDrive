@{
    RootModule        = 'EraseDrive.psm1'
    ModuleVersion     = '3.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'DarkHorse InfoSec'
    CompanyName       = 'DarkHorse InfoSec'
    Copyright         = '(c) 2026 DarkHorse InfoSec. All rights reserved.'
    Description       = 'Professional forensic disk and data destruction tool with NIST 800-88 compliant secure erasure, SSD-aware wiping, and erasure certification.'

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
        }
    }
}

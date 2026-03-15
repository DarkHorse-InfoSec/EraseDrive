#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Entry point for the EraseDrive forensic data destruction tool.

.DESCRIPTION
    Launches EraseDrive in either GUI mode (default) or CLI mode for automation.

.PARAMETER Mode
    'GUI' (default) launches the interactive graphical interface.
    'CLI' launches headless mode for automation and scripting.

.PARAMETER Operation
    CLI mode only. The operation to perform:
    - 'UserWipe'  : Forensic user data wipe (system remains bootable)
    - 'DiskErase' : Complete disk erasure (non-system disks only)

.PARAMETER DiskNumber
    CLI mode, DiskErase only. The disk number to erase.

.PARAMETER Method
    Wipe method: 'Standard' (fast) or 'Secure' (multi-pass overwrite).
    Default: 'Standard'

.PARAMETER ClearEventLogs
    Optional switch to also clear Windows Event Logs during UserWipe.
    Default: OFF (preserves audit trail).

.PARAMETER SkipVerification
    Skip the post-erase verification pass. Not recommended.

.PARAMETER TimeoutMinutes
    Maximum number of minutes the operation is allowed to run. 0 (default) means no
    timeout. Passed through to Invoke-SecureDiskErase in CLI mode.

.PARAMETER Force
    Bypasses ShouldProcess confirmation prompts for unattended automation (MDT/SCCM).
    When specified, no interactive confirmation is required.

.PARAMETER Confirm
    CLI mode only. Required flag to confirm destructive operation.
    Must be explicitly passed to prevent accidental execution.

.EXAMPLE
    # Launch GUI
    .\Start-EraseDrive.ps1

.EXAMPLE
    # CLI: Interactive erase with confirmation prompt
    .\Start-EraseDrive.ps1 -Mode CLI -Operation DiskErase -DiskNumber 2 -Method Secure

.EXAMPLE
    # CLI: Automated erase (no confirmation prompt, for MDT/SCCM)
    .\Start-EraseDrive.ps1 -Mode CLI -Operation DiskErase -DiskNumber 2 -Method Secure -Force

.EXAMPLE
    # CLI: Secure user wipe with event log clearing
    .\Start-EraseDrive.ps1 -Mode CLI -Operation UserWipe -Method Secure -ClearEventLogs -Confirm

.NOTES
    CRITICAL: This tool permanently destroys data. There is no undo.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('GUI', 'CLI')]
    [string]$Mode = 'GUI',

    [ValidateSet('UserWipe', 'DiskErase')]
    [string]$Operation,

    [int]$DiskNumber = -1,

    [ValidateSet('Standard', 'Secure')]
    [string]$Method = 'Standard',

    [switch]$ClearEventLogs,

    [switch]$SkipVerification,

    [int]$TimeoutMinutes = 0,

    [switch]$Force
)

# Import the module
$modulePath = Join-Path $PSScriptRoot 'EraseDrive'
Import-Module $modulePath -Force

if ($Mode -eq 'GUI') {
    Start-EraseDriveGUI
}
else {
    # CLI mode
    if (-not $Operation) {
        Write-Error "CLI mode requires -Operation parameter. Use 'UserWipe' or 'DiskErase'."
        exit 1
    }

    if ($Force) {
        $ConfirmPreference = 'None'
        Write-OperationLog "FORCE mode: Confirmation prompts suppressed by operator" 'INFO'
    }

    Write-OperationLog "CLI mode started: Operation=$Operation, Method=$Method" 'INFO'

    switch ($Operation) {
        'UserWipe' {
            if ($PSCmdlet.ShouldProcess('All user profiles', 'Forensic User Data Wipe')) {
                Write-Host "`n=== FORENSIC USER DATA WIPE ===" -ForegroundColor Red
                Write-Host "Method: $Method" -ForegroundColor Yellow
                Write-Host "Clear Event Logs: $ClearEventLogs" -ForegroundColor Yellow
                Write-Host ""

                $result = Invoke-ForensicUserDataWipe -WipeMethod $Method -ClearEventLogs:$ClearEventLogs
                if ($result.Success) {
                    Write-Host "`nWipe completed successfully." -ForegroundColor Green
                    $logPath = Join-Path $env:ProgramData 'DarkHorse\EraseDrive\EraseDrive.log'
                    Write-Host "Log: $logPath" -ForegroundColor Cyan
                    if ($result.CertificatePath) {
                        Write-Host "Certificate: $($result.CertificatePath)" -ForegroundColor Cyan
                    }
                    exit 0
                }
                else {
                    Write-Error "Wipe failed: $($result.Message)"
                    exit 1
                }
            }
        }
        'DiskErase' {
            if ($DiskNumber -lt 0) {
                Write-Error "DiskErase requires -DiskNumber parameter."
                exit 1
            }

            $safetyCheck = Test-DiskSafeToErase -DiskNumber $DiskNumber
            if (-not $safetyCheck.Safe) {
                Write-Error "Disk $DiskNumber is not safe to erase: $($safetyCheck.Reason)"
                exit 1
            }

            $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
            $diskDesc = "Disk $DiskNumber ($($disk.FriendlyName), $([math]::Round($disk.Size / 1GB, 2)) GB)"

            if ($PSCmdlet.ShouldProcess($diskDesc, 'Complete Disk Erasure')) {
                Write-Host "`n=== COMPLETE DISK ERASURE ===" -ForegroundColor Red
                Write-Host "Target: $diskDesc" -ForegroundColor Yellow
                Write-Host "Method: $Method" -ForegroundColor Yellow
                Write-Host ""

                $result = Invoke-SecureDiskErase -DiskNumber $DiskNumber -EraseMethod $Method -SkipVerification:$SkipVerification -TimeoutMinutes $TimeoutMinutes
                if ($result.Success) {
                    Write-Host "`nErase completed successfully." -ForegroundColor Green
                    $logPath = Join-Path $env:ProgramData 'DarkHorse\EraseDrive\EraseDrive.log'
                    Write-Host "Log: $logPath" -ForegroundColor Cyan
                    if ($result.CertificatePath) {
                        Write-Host "Certificate: $($result.CertificatePath)" -ForegroundColor Cyan
                    }
                    exit 0
                }
                else {
                    Write-Error "Erase failed: $($result.Message)"
                    exit 1
                }
            }
        }
    }
}

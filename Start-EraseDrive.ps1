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
    - 'UserWipe'    : Forensic user data wipe (system remains bootable)
    - 'DiskErase'   : Complete disk erasure (non-system disks only)
    - 'ReissueWipe' : Full device reissue or resale wipe. Removes all users, network
                      identity, credentials, shadow copies and machine history while
                      leaving Windows installed. Runs offline from WinPE via
                      -OfflineRoot, which is the only mode that can be complete.
                      Exit codes: 0 complete, 2 succeeded with remnants, 1 failed.

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
    # Boot the WinPE media, then wipe the internal Windows install for reissue.
    # This is the recommended form: nothing on the target is running, so every profile
    # can be removed and no remnants are left behind.
    .\Start-EraseDrive.ps1 -Mode CLI -Operation ReissueWipe -OfflineRoot C:\ -RemoveFromDomain -Method Secure -Force

.EXAMPLE
    # Live reissue wipe with sysprep, so the device boots to out-of-box setup and
    # shuts down ready to hand to the next person.
    .\Start-EraseDrive.ps1 -Mode CLI -Operation ReissueWipe -RemoveFromDomain -Generalize -Force

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

    [ValidateSet('UserWipe', 'DiskErase', 'ReissueWipe')]
    [string]$Operation,

    # ReissueWipe only. Root of an offline Windows volume when running from WinPE,
    # for example 'C:\'. Omit to wipe the running system.
    [string]$OfflineRoot,

    # ReissueWipe only. Remove the DEVICE from its Active Directory domain. No
    # Active Directory objects are modified; user accounts are untouched.
    [switch]$RemoveFromDomain,

    [ValidatePattern('^[A-Za-z0-9\-]{1,15}$')]
    [string]$WorkgroupName = 'WORKGROUP',

    # ReissueWipe only. Run sysprep /generalize so the device boots to out-of-box setup.
    [switch]$Generalize,

    [ValidateSet('Shutdown', 'Reboot', 'Quit')]
    [string]$GeneralizeAction = 'Shutdown',

    # Where to write the log and the certificate of destruction. Defaults to the
    # directory this script was launched from, which on the intended deployment is
    # the USB stick rather than the machine being wiped.
    [string]$EvidencePath,

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

# Surface active license tier in both GUI and CLI startup paths
$licenseAtStart = & (Get-Module EraseDrive) { Test-EraseDriveLicense -Silent }
$tierAtStart = $licenseAtStart.Tier

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

    $tierBannerColor = if ($tierAtStart -eq 'Free') { 'DarkYellow' } else { 'Green' }
    Write-Host "EraseDrive license tier: $tierAtStart" -ForegroundColor $tierBannerColor
    if ($tierAtStart -eq 'Free') {
        Write-Host "  (Free tier produces .txt certificates only. Upgrade at erasedrive.io for signed PDF certificates.)" -ForegroundColor DarkYellow
    }

    Write-OperationLog "CLI mode started: Operation=$Operation, Method=$Method, Tier=$tierAtStart" 'INFO'

    switch ($Operation) {
        'ReissueWipe' {
            $modeLabel = $(if ($OfflineRoot) { "OFFLINE ($OfflineRoot)" } else { 'LIVE (running system)' })

            Write-Host "`n=== DEVICE REISSUE WIPE ===" -ForegroundColor Red
            Write-Host "Mode:             $modeLabel" -ForegroundColor Yellow
            Write-Host "Method:           $Method" -ForegroundColor Yellow
            Write-Host "Remove from domain: $RemoveFromDomain" -ForegroundColor Yellow
            Write-Host "Generalize:       $Generalize" -ForegroundColor Yellow
            Write-Host ""

            if (-not $OfflineRoot) {
                Write-Host "WARNING: a live wipe cannot be complete. The operator's own profile," -ForegroundColor Yellow
                Write-Host "         the cached domain credential store and pagefile.sys all survive." -ForegroundColor Yellow
                Write-Host "         Boot the EraseDrive WinPE media for a full wipe." -ForegroundColor Yellow
                Write-Host ""
            }

            $reissueArgs = @{
                WipeMethod       = $Method
                WorkgroupName    = $WorkgroupName
                GeneralizeAction = $GeneralizeAction
            }
            if ($OfflineRoot)      { $reissueArgs['OfflineRoot'] = $OfflineRoot }
            if ($EvidencePath)     { $reissueArgs['EvidencePath'] = $EvidencePath }
            if ($RemoveFromDomain) { $reissueArgs['RemoveFromDomain'] = $true }
            if ($Generalize)       { $reissueArgs['Generalize'] = $true }
            if ($ClearEventLogs)   { $reissueArgs['ClearEventLogs'] = $true }

            $result = Invoke-DeviceReissueWipe @reissueArgs

            Write-Host ""
            Write-Host $result.Message -ForegroundColor $(if ($result.Complete) { 'Green' } else { 'Yellow' })
            Write-Host "Evidence: $($result.EvidenceRoot)" -ForegroundColor Cyan
            if ($result.CertificatePath) {
                Write-Host "Certificate: $($result.CertificatePath)" -ForegroundColor Cyan
            }

            if ($result.Unreachable.Count -gt 0) {
                Write-Host ""
                Write-Host "REMNANTS NOT REMOVED ($($result.Unreachable.Count)):" -ForegroundColor Yellow
                $result.Unreachable | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
            }

            if ($result.PendingReboot) {
                Write-Host ""
                Write-Host "A clean shutdown is REQUIRED before this device is handed over." -ForegroundColor Yellow
            }

            # Exit 0 only on a complete wipe. A partial wipe reported as success is how a
            # device gets handed over with the previous user's data still on it.
            if ($result.Success -and $result.Complete) { exit 0 }
            elseif ($result.Success) { exit 2 }
            else { exit 1 }
        }

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
                        Write-Host "Certificate (TXT): $($result.CertificatePath)" -ForegroundColor Cyan
                    }
                    if ($result.PSObject.Properties['PdfCertificatePath'] -and $result.PdfCertificatePath) {
                        Write-Host "Certificate (PDF): $($result.PdfCertificatePath)" -ForegroundColor Cyan
                    }
                    elseif ($tierAtStart -eq 'Free') {
                        Write-Host "Free tier: no PDF certificate. Upgrade at erasedrive.io for signed PDFs." -ForegroundColor DarkYellow
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
                        Write-Host "Certificate (TXT): $($result.CertificatePath)" -ForegroundColor Cyan
                    }
                    if ($result.PSObject.Properties['PdfCertificatePath'] -and $result.PdfCertificatePath) {
                        Write-Host "Certificate (PDF): $($result.PdfCertificatePath)" -ForegroundColor Cyan
                    }
                    elseif ($tierAtStart -eq 'Free') {
                        Write-Host "Free tier: no PDF certificate. Upgrade at erasedrive.io for signed PDFs." -ForegroundColor DarkYellow
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

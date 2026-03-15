function Invoke-ForensicUserDataWipe {
    <#
    .SYNOPSIS
        Performs a forensic wipe of all user data from the system while leaving it bootable.

    .DESCRIPTION
        Removes all non-system user profiles, their registry entries, local user accounts,
        temporary files, browser data, Windows Search index, recent documents, and jump lists.
        The system remains bootable but is returned to a clean state with no user traces.

        When the Secure wipe method is selected, free space on the system drive is overwritten
        after file deletion to prevent forensic data recovery. An erasure certificate is
        generated upon completion.

        This function replaces the legacy Invoke-ForensicUserDataWipe with the following
        improvements:
        - Uses Get-CimInstance instead of deprecated Get-WmiObject
        - Fixes O(n*m) process killing with Get-Process -IncludeUserName
        - Event log clearing is opt-in (was always-on, destroying audit trails)
        - Logs to ProgramData via Write-OperationLog (not Desktop)
        - Full ShouldProcess / -WhatIf support
        - Returns structured PSCustomObject instead of tuple arrays

    .PARAMETER WipeMethod
        The wipe intensity. 'Standard' deletes files normally. 'Secure' additionally
        overwrites free space on the system drive after deletion to hinder forensic recovery.
        Default: Standard

    .PARAMETER ClearEventLogs
        When specified, clears all Windows Event Logs as part of the wipe. This is OFF by
        default to preserve the audit trail. Only enable this when forensic log destruction
        is explicitly required.

    .PARAMETER ReportProgress
        Optional scriptblock callback invoked with progress updates. Receives a hashtable
        with keys: PercentComplete (int), Status (string), CurrentOperation (string).

    .OUTPUTS
        PSCustomObject with properties:
            Success          [bool]     - Whether the wipe completed without fatal errors
            Message          [string]   - Summary message
            ProfilesRemoved  [string[]] - Names of user profiles that were removed
            CertificatePath  [string]   - Path to the erasure certificate file
            Duration         [timespan] - Total elapsed time

    .EXAMPLE
        Invoke-ForensicUserDataWipe -WipeMethod Standard

        Performs a standard forensic user data wipe, preserving event logs.

    .EXAMPLE
        Invoke-ForensicUserDataWipe -WipeMethod Secure -ClearEventLogs

        Performs a secure wipe with free-space overwrite and clears all event logs.

    .EXAMPLE
        Invoke-ForensicUserDataWipe -WipeMethod Secure -WhatIf

        Shows what the secure wipe would do without making any changes.

    .EXAMPLE
        Invoke-ForensicUserDataWipe -WipeMethod Secure -ReportProgress {
            param($info)
            Write-Progress -Activity 'Forensic Wipe' -Status $info.Status -PercentComplete $info.PercentComplete
        }

        Performs a secure wipe with progress reporting via Write-Progress.

    .NOTES
        Requires Administrator privileges.
        Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter()]
        [ValidateSet('Standard', 'Secure')]
        [string]$WipeMethod = 'Standard',

        [Parameter()]
        [switch]$ClearEventLogs,

        [Parameter()]
        [scriptblock]$ReportProgress
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $profilesRemoved = [System.Collections.Generic.List[string]]::new()
    $certificatePath = $null
    $operationLock = $null

    # Helper to invoke progress callback safely
    $reportStep = {
        param([int]$Percent, [string]$Status, [string]$Operation)
        if ($ReportProgress) {
            try {
                & $ReportProgress @{
                    PercentComplete  = $Percent
                    Status           = $Status
                    CurrentOperation = $Operation
                }
            }
            catch { }
        }
    }

    try {
        # ── Acquire operation lock ─────────────────────────────────────
        $operationLock = Enter-OperationLock -OperationName 'ForensicUserDataWipe'

        if (-not $operationLock.Acquired) {
            $stopwatch.Stop()
            return [PSCustomObject]@{
                Success         = $false
                Message         = $operationLock.Message
                ProfilesRemoved = [string[]]@()
                CertificatePath = $null
                Duration        = $stopwatch.Elapsed
            }
        }
        Write-OperationLog -Message "Forensic user data wipe started (Method: $WipeMethod, ClearEventLogs: $ClearEventLogs)" -LogLevel 'INFO'
        Write-AuditLog -EventType 'OperationStarted' -Message "Forensic user data wipe started (Method: $WipeMethod, ClearEventLogs: $ClearEventLogs)" -TargetDescription 'System drive user data'
        & $reportStep 0 'Initializing' 'Enumerating user profiles'

        # ── 1. Enumerate non-system user profiles ──────────────────────────
        $userProfiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {
            -not $_.Special -and
            $_.LocalPath -notmatch '\\(Administrator|Guest|DefaultUser|Default|Public)$' -and
            $null -ne $_.LocalPath -and
            $_.LocalPath -ne "$env:SystemRoot\system32\config\systemprofile" -and
            $_.LocalPath -ne "$env:SystemRoot\ServiceProfiles\LocalService" -and
            $_.LocalPath -ne "$env:SystemRoot\ServiceProfiles\NetworkService"
        }

        if (-not $userProfiles) {
            Write-OperationLog -Message 'No non-system user profiles found to remove.' -LogLevel 'INFO'
        }

        # ── 2. Kill processes owned by target users (O(n) instead of O(n*m)) ─
        & $reportStep 5 'Stopping user processes' 'Identifying running processes'

        if ($userProfiles -and $PSCmdlet.ShouldProcess('User processes', 'Stop all processes owned by target users')) {
            try {
                $targetUserNames = $userProfiles | ForEach-Object { Split-Path $_.LocalPath -Leaf }
                $allProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
                foreach ($proc in $allProcesses) {
                    if ($proc.UserName) {
                        $procUser = ($proc.UserName -split '\\')[-1]
                        if ($procUser -in $targetUserNames) {
                            try {
                                $proc | Stop-Process -Force -ErrorAction SilentlyContinue
                            }
                            catch { }
                        }
                    }
                }
                Write-OperationLog -Message "Stopped processes for users: $($targetUserNames -join ', ')" -LogLevel 'INFO'
            }
            catch {
                Write-OperationLog -Message "Warning stopping user processes: $($_.Exception.Message)" -LogLevel 'WARNING'
            }
        }

        # ── 3. Remove each user profile ────────────────────────────────────
        $profileIndex = 0
        $profileCount = @($userProfiles).Count

        foreach ($profile in $userProfiles) {
            $profileIndex++
            $userPath = $profile.LocalPath
            $userName = Split-Path $userPath -Leaf
            $userSID = $profile.SID
            $pctBase = 10 + [int](($profileIndex / [math]::Max($profileCount, 1)) * 30)

            & $reportStep $pctBase "Removing profile $profileIndex of $profileCount" $userName

            if (-not $PSCmdlet.ShouldProcess("User profile: $userName ($userPath)", 'Remove')) {
                continue
            }

            Write-OperationLog -Message "Removing user profile: $userName (SID: $userSID)" -LogLevel 'INFO'

            try {
                # Remove loaded registry hive
                $regPath = "Registry::HKEY_USERS\$userSID"
                if (Test-Path $regPath) {
                    Remove-Item $regPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-OperationLog -Message "Removed registry hive for $userName" -LogLevel 'INFO'
                }

                # Take ownership and remove profile directory
                if (Test-Path $userPath) {
                    takeown /f "$userPath" /r /d y 2>&1 | Out-Null
                    icacls "$userPath" /grant administrators:F /t /c /q 2>&1 | Out-Null
                    Remove-Item $userPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-OperationLog -Message "Removed profile directory: $userPath" -LogLevel 'INFO'
                }

                # Remove profile registry entry from ProfileList
                $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSID"
                if (Test-Path $profileListPath) {
                    Remove-Item $profileListPath -Force -ErrorAction SilentlyContinue
                    Write-OperationLog -Message "Removed profile registry entry for $userName" -LogLevel 'INFO'
                }

                # Remove local user account if it exists
                try {
                    $localUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
                    if ($localUser) {
                        Remove-LocalUser -Name $userName -ErrorAction SilentlyContinue
                        Write-OperationLog -Message "Removed local user account: $userName" -LogLevel 'INFO'
                    }
                }
                catch {
                    Write-OperationLog -Message "Could not remove local account (may be domain): $userName" -LogLevel 'WARNING'
                }

                $profilesRemoved.Add($userName)
            }
            catch {
                Write-OperationLog -Message "Error removing profile ${userName}: $($_.Exception.Message)" -LogLevel 'ERROR'
            }
        }

        # ── 4. Clean system-wide temporary locations ───────────────────────
        & $reportStep 45 'Cleaning temporary files' 'System temp locations'

        $tempLocations = @(
            "$env:WINDIR\Temp",
            "$env:WINDIR\Prefetch",
            "$env:WINDIR\SoftwareDistribution\Download",
            "$env:ProgramData\Microsoft\Windows\WER"
        )

        foreach ($location in $tempLocations) {
            if ((Test-Path $location) -and $PSCmdlet.ShouldProcess($location, 'Clean temporary files')) {
                try {
                    Get-ChildItem $location -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    Write-OperationLog -Message "Cleaned temp location: $location" -LogLevel 'INFO'
                }
                catch {
                    Write-OperationLog -Message "Failed to fully clean: $location" -LogLevel 'WARNING'
                }
            }
        }

        # ── 5. Clean system browser data paths ────────────────────────────
        & $reportStep 55 'Cleaning browser data' 'System-level browser caches'

        $systemBrowserPaths = @(
            "$env:ProgramData\Google\Chrome",
            "$env:ProgramData\Microsoft\Edge",
            "$env:ProgramData\Mozilla\Firefox"
        )

        foreach ($browserPath in $systemBrowserPaths) {
            if ((Test-Path $browserPath) -and $PSCmdlet.ShouldProcess($browserPath, 'Clean browser data')) {
                try {
                    Get-ChildItem $browserPath -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '(User Data|Profiles|Cache)' } |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    Write-OperationLog -Message "Cleaned browser data: $browserPath" -LogLevel 'INFO'
                }
                catch { }
            }
        }

        # ── 6. Clear recent documents and jump lists ──────────────────────
        & $reportStep 60 'Clearing recent documents' 'Recent items and jump lists'

        $recentLocations = @(
            "$env:ProgramData\Microsoft\Windows\Recent",
            "$env:WINDIR\Recent"
        )

        foreach ($location in $recentLocations) {
            if ((Test-Path $location) -and $PSCmdlet.ShouldProcess($location, 'Clear recent documents')) {
                try {
                    Remove-Item "$location\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-OperationLog -Message "Cleared recent documents: $location" -LogLevel 'INFO'
                }
                catch { }
            }
        }

        # ── 7. Run Windows Disk Cleanup ───────────────────────────────────
        & $reportStep 65 'Running Disk Cleanup' 'cleanmgr'

        if ($PSCmdlet.ShouldProcess('Windows Disk Cleanup', 'Execute cleanmgr /sagerun:1')) {
            try {
                Start-Process 'cleanmgr' -ArgumentList '/sagerun:1' -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                Write-OperationLog -Message 'Executed Windows Disk Cleanup' -LogLevel 'INFO'
            }
            catch {
                Write-OperationLog -Message "Failed to run Disk Cleanup: $($_.Exception.Message)" -LogLevel 'WARNING'
            }
        }

        # ── 8. Clear and rebuild Windows Search index ─────────────────────
        & $reportStep 70 'Rebuilding search index' 'Windows Search'

        if ($PSCmdlet.ShouldProcess('Windows Search index', 'Clear and rebuild')) {
            try {
                Stop-Service 'WSearch' -Force -ErrorAction SilentlyContinue
                $searchPath = "$env:ProgramData\Microsoft\Search\Data"
                if (Test-Path $searchPath) {
                    Remove-Item "$searchPath\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-OperationLog -Message 'Cleared Windows Search index' -LogLevel 'INFO'
                }
                Start-Service 'WSearch' -ErrorAction SilentlyContinue
            }
            catch {
                Write-OperationLog -Message "Failed to clear search index: $($_.Exception.Message)" -LogLevel 'WARNING'
            }
        }

        # ── 9. Optionally clear event logs (opt-in) ──────────────────────
        if ($ClearEventLogs) {
            & $reportStep 75 'Clearing event logs' 'Windows Event Logs'

            if ($PSCmdlet.ShouldProcess('All Windows Event Logs', 'Clear')) {
                try {
                    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
                        try { wevtutil cl $_.LogName 2>&1 | Out-Null } catch { }
                    }
                    Write-OperationLog -Message 'Cleared all Windows Event Logs (user requested)' -LogLevel 'WARNING'
                }
                catch {
                    Write-OperationLog -Message 'Failed to clear some event logs' -LogLevel 'WARNING'
                }
            }
        }

        # ── 10. Secure free-space overwrite (Secure method only) ──────────
        if ($WipeMethod -eq 'Secure') {
            & $reportStep 80 'Overwriting free space' 'Secure free-space overwrite on system drive'

            if ($PSCmdlet.ShouldProcess('System drive free space', 'Secure overwrite')) {
                try {
                    $systemDrive = $env:SystemDrive  # e.g. "C:"
                    Write-OperationLog -Message "Starting secure free-space overwrite on $systemDrive" -LogLevel 'INFO'

                    $overwriteResult = Invoke-SecureOverwrite -TargetPath "$systemDrive\" -Passes 1 -ReportProgress {
                        param($info)
                        & $reportStep ([int](80 + ($info.PercentComplete * 0.15))) 'Overwriting free space' "Pass $($info.Pass) of $($info.TotalPasses)"
                    }

                    if ($overwriteResult.Success) {
                        Write-OperationLog -Message "Free-space overwrite complete: $($overwriteResult.BytesOverwritten) bytes, $($overwriteResult.Duration)" -LogLevel 'SUCCESS'
                    }
                    else {
                        Write-OperationLog -Message "Free-space overwrite issue: $($overwriteResult.Message)" -LogLevel 'WARNING'
                    }
                }
                catch {
                    Write-OperationLog -Message "Free-space overwrite failed: $($_.Exception.Message)" -LogLevel 'WARNING'
                }
            }
        }

        # ── 11. Generate erasure certificate ──────────────────────────────
        & $reportStep 95 'Generating certificate' 'Erasure certificate'

        if ($PSCmdlet.ShouldProcess('Erasure certificate', 'Generate')) {
            try {
                $systemDisk = Get-CimInstance -ClassName Win32_DiskDrive | Where-Object {
                    $_.DeviceID -eq '\\.\PHYSICALDRIVE0'
                } | Select-Object -First 1

                $diskSerial = $(if ($systemDisk) { $systemDisk.SerialNumber } else { 'Unknown' })
                $diskModel = $(if ($systemDisk) { $systemDisk.Model } else { 'Unknown' })
                $diskSizeGB = $(if ($systemDisk) { [math]::Round($systemDisk.Size / 1GB, 2) } else { 0 })

                $certResult = New-ErasureCertificate `
                    -OperationType 'UserWipe' `
                    -TargetDescription "System drive user data wipe ($($profilesRemoved.Count) profiles removed)" `
                    -Method $WipeMethod `
                    -DiskSerial $diskSerial `
                    -DiskModel $diskModel `
                    -DiskSizeGB $diskSizeGB `
                    -VerificationResult $null `
                    -OperatorName ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

                if ($certResult.Success) {
                    $certificatePath = $certResult.FilePath
                    Write-OperationLog -Message "Erasure certificate generated: $certificatePath" -LogLevel 'SUCCESS'
                    Write-AuditLog -EventType 'CertificateGenerated' -Message "Certificate path: $certificatePath" -TargetDescription 'System drive user data'
                }
            }
            catch {
                Write-OperationLog -Message "Failed to generate certificate: $($_.Exception.Message)" -LogLevel 'WARNING'
            }
        }

        # ── Done ──────────────────────────────────────────────────────────
        $stopwatch.Stop()
        & $reportStep 100 'Complete' 'Forensic wipe finished'

        $message = "Forensic user data wipe completed successfully. $($profilesRemoved.Count) profile(s) removed."
        Write-OperationLog -Message $message -LogLevel 'SUCCESS'
        Write-AuditLog -EventType 'OperationCompleted' -Message $message -TargetDescription 'System drive user data'

        [PSCustomObject]@{
            Success         = $true
            Message         = $message
            ProfilesRemoved = [string[]]$profilesRemoved.ToArray()
            CertificatePath = $certificatePath
            Duration        = $stopwatch.Elapsed
        }
    }
    catch {
        $stopwatch.Stop()
        $errorMessage = "Forensic user data wipe failed: $($_.Exception.Message)"
        Write-OperationLog -Message $errorMessage -LogLevel 'ERROR'
        Write-AuditLog -EventType 'OperationFailed' -Message $errorMessage -TargetDescription 'System drive user data'

        [PSCustomObject]@{
            Success         = $false
            Message         = $errorMessage
            ProfilesRemoved = [string[]]$profilesRemoved.ToArray()
            CertificatePath = $null
            Duration        = $stopwatch.Elapsed
        }
    }
    finally {
        if ($operationLock -and $operationLock.Acquired) {
            Exit-OperationLock -Mutex $operationLock.Mutex
        }
    }
}

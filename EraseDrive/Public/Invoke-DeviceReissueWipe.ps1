function Invoke-DeviceReissueWipe {
    <#
    .SYNOPSIS
        Returns a Windows device to a clean state for reissue to another person or for sale,
        keeping the operating system installed.

    .DESCRIPTION
        Removes every trace of previous users and of the owning organisation from a Windows
        device while leaving Windows itself installed and bootable. Intended for two cases:
        handing a machine to a different employee, and selling or otherwise disposing of a
        machine the business has finished with.

        It runs in either of two modes, and the difference between them is not cosmetic:

            Offline (recommended) - boot the EraseDrive WinPE media and pass -OfflineRoot.
                Nothing on the target is running, so every profile can be removed including
                the last administrator, the registry hives are ordinary files, and
                pagefile.sys and hiberfil.sys can be deleted outright.

            Live - run against the running Windows install. Convenient, and structurally
                incapable of being complete: the operator's own profile survives, the
                cached domain credential store in HKLM\SECURITY is unreadable to anything
                but SYSTEM, and the kernel holds the memory image files open. Every one of
                those gaps is reported in the result rather than glossed over.

        ACTIVE DIRECTORY IS NEVER MODIFIED. -RemoveFromDomain removes the DEVICE from the
        domain. User accounts are untouched, so the departing user signs in on their next
        machine exactly as before, and the computer object is left in place for normal
        directory cleanup. See Remove-DomainMembership for how that is enforced rather
        than merely intended.

        Order of operations is deliberate. Shadow copies and the memory image files are
        handled near the end, after the deletions, so that a snapshot taken while the wipe
        was running is itself removed. Sysprep runs last of all because it shuts the
        machine down.

    .PARAMETER OfflineRoot
        Root of an offline Windows volume, for example 'C:\' as seen from WinPE. Omit to
        operate on the running system.

    .PARAMETER WipeMethod
        Standard deletes. Secure additionally overwrites free space afterwards so deleted
        content is not forensically recoverable. Secure is substantially slower and on an
        SSD is a Clear, not a Purge; see the README on NIST 800-88 limits.

    .PARAMETER RemoveFromDomain
        Remove the device from its Active Directory domain and clear the network
        remnants that identify the organisation. Makes no directory writes.

    .PARAMETER WorkgroupName
        Workgroup to place the device in when unjoining. Default WORKGROUP.

    .PARAMETER Generalize
        Run sysprep /generalize afterwards so the device boots to out-of-box setup like a
        new machine. Consumes a rearm and requires the device to be unjoined first.
        Refuses with a stated reason rather than failing part way.

    .PARAMETER GeneralizeAction
        What sysprep does on completion: Shutdown (default), Reboot, or Quit.

    .PARAMETER ClearEventLogs
        Clear all Windows event logs. Off by default so the audit trail survives. Note
        that -Generalize clears them regardless, as part of what sysprep does.

    .PARAMETER EvidencePath
        Where to write the log and the destruction certificate. Defaults to the directory
        EraseDrive was launched from, which on the intended deployment is the USB stick.

    .PARAMETER ReportProgress
        Scriptblock receiving @{ PercentComplete; Status; CurrentOperation }.

    .OUTPUTS
        PSCustomObject:
            Success          [bool]     - True only when every step reported success
            Complete         [bool]     - True only when nothing was skipped or unreachable
            Mode             [string]   - Offline or Live
            Steps            [object[]] - Per-step results
            ProfilesRemoved  [string[]]
            ProfilesSkipped  [object[]]
            Unreachable      [string[]] - Remnants that could not be removed in this mode
            PendingReboot    [bool]
            CertificatePath  [string]
            EvidenceRoot     [string]
            Duration         [timespan]

    .EXAMPLE
        Invoke-DeviceReissueWipe -OfflineRoot 'C:\' -RemoveFromDomain -WipeMethod Secure

        From WinPE: the complete wipe. Recommended form for reissue and for resale.

    .EXAMPLE
        Invoke-DeviceReissueWipe -RemoveFromDomain -Generalize

        Live: clean the machine, take it off the domain, then generalize so it boots to
        out-of-box setup and shuts down ready to hand over.

    .EXAMPLE
        Invoke-DeviceReissueWipe -OfflineRoot 'C:\' -WhatIf

        Shows every action without performing any of them.

    .NOTES
        Requires Administrator privileges. Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter()]
        [string]$OfflineRoot,

        [Parameter()]
        [ValidateSet('Standard', 'Secure')]
        [string]$WipeMethod = 'Standard',

        [Parameter()]
        [switch]$RemoveFromDomain,

        [Parameter()]
        [ValidatePattern('^[A-Za-z0-9\-]{1,15}$')]
        [string]$WorkgroupName = 'WORKGROUP',

        [Parameter()]
        [switch]$Generalize,

        [Parameter()]
        [ValidateSet('Shutdown', 'Reboot', 'Quit')]
        [string]$GeneralizeAction = 'Shutdown',

        [Parameter()]
        [switch]$ClearEventLogs,

        [Parameter()]
        [string]$EvidencePath,

        [Parameter()]
        [scriptblock]$ReportProgress
    )

    $stopwatch     = [System.Diagnostics.Stopwatch]::StartNew()
    $steps         = [System.Collections.Generic.List[object]]::new()
    $unreachable   = [System.Collections.Generic.List[string]]::new()
    $operationLock = $null
    $certPath      = $null
    $pendingReboot = $false

    $report = {
        param([int]$Percent, [string]$Status, [string]$Operation)
        if ($ReportProgress) {
            try { & $ReportProgress @{ PercentComplete = $Percent; Status = $Status; CurrentOperation = $Operation } } catch { }
        }
    }

    # Records a step result and folds its warnings into the run-level view.
    $record = {
        param($Result)
        if ($null -eq $Result) { return }
        $steps.Add($Result)

        if ($Result.PSObject.Properties.Name -contains 'Unreachable') {
            foreach ($item in @($Result.Unreachable)) {
                if ($item) { $unreachable.Add($item) }
            }
        }

        foreach ($w in @($Result.Warnings)) {
            if ($w) { Write-OperationLog -Message "[$($Result.Name)] $w" -LogLevel 'WARNING' }
        }
    }

    try {
        # ---- 1. Resolve the target ---------------------------------------
        & $report 0 'Resolving target' 'Locating the Windows installation'

        $context = Get-TargetContext -OfflineRoot $OfflineRoot
        if (-not $context.Valid) {
            $stopwatch.Stop()
            Write-OperationLog -Message "Target resolution failed: $($context.Reason)" -LogLevel 'ERROR'
            return [PSCustomObject]@{
                Success = $false; Complete = $false
                Mode = $(if ($OfflineRoot) { 'Offline' } else { 'Live' })
                Steps = @(); ProfilesRemoved = [string[]]@(); ProfilesSkipped = @()
                Unreachable = [string[]]@(); PendingReboot = $false
                CertificatePath = $null; EvidenceRoot = $null
                Duration = $stopwatch.Elapsed
                Message = $context.Reason
            }
        }

        $mode = $(if ($context.IsOffline) { 'Offline' } else { 'Live' })

        # ---- 2. Decide where the evidence goes ---------------------------
        # Done before anything is destroyed, so a failure to secure the audit trail is
        # discovered while the machine is still intact.
        $evidence = Set-EraseDriveEvidenceRoot -Path $EvidencePath -Context $context
        if (-not $evidence.Success) {
            Write-OperationLog -Message $evidence.Message -LogLevel 'ERROR'
        }

        Write-OperationLog -Message "Device reissue wipe starting. Mode: $mode. Target: $($context.Description)" -LogLevel 'INFO'
        Write-AuditLog -EventType 'OperationStarted' -Message "Device reissue wipe ($mode, method $WipeMethod, domain removal: $RemoveFromDomain, generalize: $Generalize)" -TargetDescription $context.Description

        # ---- 3. Serialise against other EraseDrive operations -------------
        $operationLock = Enter-OperationLock -OperationName 'DeviceReissueWipe'
        if (-not $operationLock.Acquired) {
            $stopwatch.Stop()
            return [PSCustomObject]@{
                Success = $false; Complete = $false; Mode = $mode; Steps = @()
                ProfilesRemoved = [string[]]@(); ProfilesSkipped = @()
                Unreachable = [string[]]@(); PendingReboot = $false
                CertificatePath = $null; EvidenceRoot = $evidence.Root
                Duration = $stopwatch.Elapsed; Message = $operationLock.Message
            }
        }

        # ---- 4. Identify what must not be touched -------------------------
        $protected = Get-ProtectedSessionPrincipal -Context $context

        if (-not $protected.IsEmpty) {
            Write-OperationLog -Message "$($protected.Sids.Count) account(s) are in use and will be preserved. A live wipe cannot be complete; boot the WinPE media for a full wipe." -LogLevel 'WARNING'
        }

        # ---- 5. Profiles --------------------------------------------------
        & $report 10 'Removing user profiles' 'User data'
        $profileResult = Remove-UserProfileData -Context $context -Protected $protected -ReportProgress {
            param($info)
            & $report ([int](10 + ($info.PercentComplete * 0.2))) 'Removing user profiles' $info.CurrentOperation
        }
        $steps.Add([PSCustomObject]@{
            Name = 'UserProfiles'
            Success = ($profileResult.Failed.Count -eq 0)
            ItemsRemoved = $profileResult.Removed.Count
            Warnings = @($profileResult.Failed | ForEach-Object { "Failed: $($_.Name) - $($_.Reason)" })
            Message = "$($profileResult.Removed.Count) removed, $($profileResult.Skipped.Count) skipped, $($profileResult.Failed.Count) failed."
        })

        foreach ($skip in @($profileResult.Skipped)) {
            $unreachable.Add("User profile '$($skip.Name)': $($skip.Reason)")
        }
        foreach ($acct in @($profileResult.LocalAccountsNotRemoved)) {
            $unreachable.Add("Local account entry for '$acct' remains in the SAM. Offline mode does not edit SAM; boot the machine and remove it, or use -Generalize.")
        }

        # ---- 6. Credentials ------------------------------------------------
        # After profiles, because the per-profile DPAPI material goes with the profile and
        # this step handles what is left outside them.
        & $report 35 'Destroying cached credentials' 'Credential stores'
        & $record (Clear-CredentialRemnant -Context $context)

        # ---- 7. Domain and network ------------------------------------------
        if ($RemoveFromDomain) {
            & $report 45 'Removing from the domain' 'Domain membership'
            $domainResult = Remove-DomainMembership -Context $context -WorkgroupName $WorkgroupName
            & $record $domainResult
            if ($domainResult.RequiresBootToComplete) { $pendingReboot = $true }
        }
        else {
            Write-OperationLog -Message 'Domain removal not requested; domain membership and network identity are left in place.' -LogLevel 'INFO'
        }

        & $report 52 'Clearing network history' 'Wireless, VPN, proxy and network history'
        & $record (Clear-NetworkRemnant -Context $context)

        # ---- 8. Machine history ----------------------------------------------
        & $report 60 'Clearing device history' 'USB history, timeline, caches, Windows.old'
        & $record (Clear-DeviceHistory -Context $context)

        & $report 68 'Emptying recycle bins' 'All volumes'
        & $record (Clear-RecycleBinAllVolume -Context $context)

        # ---- 9. Shadow copies, late by design --------------------------------
        # Anything deleted above is still present in a shadow copy taken beforehand, and a
        # snapshot may have been created while this run was in progress. Removing them
        # here covers both.
        & $report 74 'Deleting shadow copies' 'Volume shadow copies and restore points'
        & $record (Remove-ShadowCopy -Context $context)

        # ---- 10. Memory images -----------------------------------------------
        & $report 80 'Removing memory image files' 'pagefile, hiberfil, swapfile'
        $memoryResult = Clear-PageAndHibernation -Context $context
        & $record $memoryResult
        if ($memoryResult.PendingReboot) {
            $pendingReboot = $true
            $unreachable.Add('pagefile.sys could not be deleted while Windows is running. It is scheduled for zeroing on the next clean shutdown.')
        }

        # ---- 11. Event logs, opt-in ------------------------------------------
        if ($ClearEventLogs -and -not $context.IsOffline) {
            & $report 84 'Clearing event logs' 'Windows event logs'

            if ($PSCmdlet.ShouldProcess('All Windows event logs', 'Clear')) {
                $cleared = 0
                Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
                    try { & wevtutil.exe cl $_.LogName 2>&1 | Out-Null; $cleared++ } catch { }
                }
                $steps.Add([PSCustomObject]@{
                    Name = 'EventLogs'; Success = $true; ItemsRemoved = $cleared
                    Warnings = @(); Message = "Cleared $cleared event log(s)."
                })
                Write-OperationLog -Message "Cleared $cleared event log(s) at operator request." -LogLevel 'WARNING'
            }
        }

        # ---- 12. Free space overwrite ----------------------------------------
        if ($WipeMethod -eq 'Secure') {
            & $report 86 'Overwriting free space' 'Secure overwrite'

            if ($PSCmdlet.ShouldProcess("$($context.Root) free space", 'Secure overwrite')) {
                try {
                    $overwrite = Invoke-SecureOverwrite -TargetPath $context.Root -Passes 1 -ReportProgress {
                        param($info)
                        & $report ([int](86 + ($info.PercentComplete * 0.08))) 'Overwriting free space' "Pass $($info.Pass) of $($info.TotalPasses)"
                    }

                    $steps.Add([PSCustomObject]@{
                        Name = 'FreeSpaceOverwrite'; Success = [bool]$overwrite.Success
                        ItemsRemoved = 0; Warnings = @($(if (-not $overwrite.Success) { $overwrite.Message } else { $null })) | Where-Object { $_ }
                        Message = "Overwrote $($overwrite.BytesOverwritten) bytes of free space."
                    })
                }
                catch {
                    $steps.Add([PSCustomObject]@{
                        Name = 'FreeSpaceOverwrite'; Success = $false; ItemsRemoved = 0
                        Warnings = @($_.Exception.Message); Message = 'Free space overwrite failed.'
                    })
                }
            }
        }

        # ---- 13. Certificate, before anything that shuts the machine down ----
        & $report 94 'Generating certificate' 'Certificate of destruction'

        $overallSuccess = -not ($steps | Where-Object { -not $_.Success })

        if ($PSCmdlet.ShouldProcess('Certificate of destruction', 'Generate')) {
            try {
                $notes = @(
                    "Mode: $mode",
                    "Target: $($context.Description)",
                    "Profiles removed: $($profileResult.Removed -join ', ')",
                    "Domain removal requested: $RemoveFromDomain",
                    'Active Directory objects modified: NONE'
                )

                if ($unreachable.Count -gt 0) {
                    $notes += 'REMNANTS NOT REMOVED:'
                    $notes += @($unreachable | ForEach-Object { "  - $_" })
                }

                $cert = New-ErasureCertificate `
                    -OperationType 'ReissueWipe' `
                    -TargetDescription $context.Description `
                    -Method $WipeMethod `
                    -VerificationResult $null `
                    -AdditionalNotes ($notes -join [Environment]::NewLine)

                if ($cert.Success) {
                    $certPath = $cert.FilePath
                    Write-AuditLog -EventType 'CertificateGenerated' -Message "Reissue wipe certificate: $certPath" -TargetDescription $context.Description
                }
            }
            catch {
                Write-OperationLog -Message "Could not generate the destruction certificate: $($_.Exception.Message)" -LogLevel 'WARNING'
            }
        }

        # ---- 14. Generalize, last because it shuts down ----------------------
        if ($Generalize) {
            & $report 97 'Generalizing' 'sysprep /generalize'
            $generalizeResult = Invoke-Generalize -Context $context -CompletionAction $GeneralizeAction
            & $record $generalizeResult

            if ($generalizeResult.Refused) {
                $unreachable.Add("Sysprep generalize was refused: $($generalizeResult.Reason)")
            }
        }

        # ---- Done --------------------------------------------------------------
        $stopwatch.Stop()
        & $report 100 'Complete' 'Device reissue wipe finished'

        $finalSuccess  = -not ($steps | Where-Object { -not $_.Success })
        $finalComplete = $finalSuccess -and ($unreachable.Count -eq 0)

        $summary = "Device reissue wipe finished in $($stopwatch.Elapsed.ToString('hh\:mm\:ss')). " +
                   "$($profileResult.Removed.Count) profile(s) removed. " +
                   $(if ($finalComplete) { 'No remnants reported.' } else { "$($unreachable.Count) remnant(s) could not be removed in $mode mode." })

        Write-OperationLog -Message $summary -LogLevel $(if ($finalComplete) { 'SUCCESS' } else { 'WARNING' })
        Write-AuditLog -EventType 'OperationCompleted' -Message $summary -TargetDescription $context.Description

        [PSCustomObject]@{
            Success         = $finalSuccess
            Complete        = $finalComplete
            Mode            = $mode
            Steps           = $steps.ToArray()
            ProfilesRemoved = [string[]]$profileResult.Removed
            ProfilesSkipped = $profileResult.Skipped
            Unreachable     = [string[]]$unreachable.ToArray()
            PendingReboot   = $pendingReboot
            CertificatePath = $certPath
            EvidenceRoot    = $evidence.Root
            Duration        = $stopwatch.Elapsed
            Message         = $summary
        }
    }
    catch {
        $stopwatch.Stop()
        $errorMessage = "Device reissue wipe failed: $($_.Exception.Message)"
        Write-OperationLog -Message $errorMessage -LogLevel 'ERROR'
        Write-AuditLog -EventType 'OperationFailed' -Message $errorMessage -TargetDescription $OfflineRoot

        [PSCustomObject]@{
            Success = $false; Complete = $false
            Mode = $(if ($OfflineRoot) { 'Offline' } else { 'Live' })
            Steps = $steps.ToArray(); ProfilesRemoved = [string[]]@(); ProfilesSkipped = @()
            Unreachable = [string[]]$unreachable.ToArray(); PendingReboot = $pendingReboot
            CertificatePath = $certPath; EvidenceRoot = $null
            Duration = $stopwatch.Elapsed; Message = $errorMessage
        }
    }
    finally {
        if ($operationLock -and $operationLock.Acquired) {
            Exit-OperationLock -Mutex $operationLock.Mutex
        }
    }
}

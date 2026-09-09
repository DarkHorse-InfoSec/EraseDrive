function Remove-UserProfileData {
    <#
    .SYNOPSIS
        Removes user profiles and their registry records, live or offline.

    .DESCRIPTION
        The single implementation of profile removal used by both Invoke-ForensicUserDataWipe
        (live) and Invoke-DeviceReissueWipe (live or offline). Extracted so there is one
        piece of code to keep correct rather than two that drift.

        What it removes for each targeted profile:
            - The profile directory on disk, taking ownership first when running live.
            - The loaded HKEY_USERS hive, when one is loaded.
            - The ProfileList registry record keyed on the profile SID.
            - The matching local account, live mode only. See the note below.

        Two things it deliberately does NOT do:

        System and service profiles are never candidates. They are excluded by the Special
        flag where the live API reports one, and by well-known SID prefix everywhere else,
        which is what catches them in offline mode where no such flag exists.

        In live mode, accounts named by Get-ProtectedSessionPrincipal are skipped and
        reported as Skipped with a reason. This is defect D1: the previous implementation
        would force-kill the operator's own processes and then fail to delete the profile
        it was executing from, while reporting the wipe as complete.

        Local account deletion is a live-mode operation only. Doing it offline means
        editing the SAM hive directly, which is fragile and easy to get wrong in ways that
        leave the install unbootable. Offline callers get the account names back in
        LocalAccountsNotRemoved so the orchestrator can report the gap rather than imply a
        completeness it did not deliver. For a domain-joined machine being reissued this is
        usually an empty list, because domain users have no local account to begin with.

    .PARAMETER Context
        Target context from Get-TargetContext.

    .PARAMETER Protected
        Protected principals from Get-ProtectedSessionPrincipal.

    .PARAMETER ReportProgress
        Optional scriptblock receiving @{ PercentComplete; Status; CurrentOperation }.

    .OUTPUTS
        PSCustomObject:
            Removed                 [string[]]
            Skipped                 [PSCustomObject[]] - Name, Sid, Reason
            Failed                  [PSCustomObject[]] - Name, Sid, Reason
            LocalAccountsNotRemoved [string[]]
            Complete                [bool] - True only when nothing was skipped or failed

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [PSCustomObject]$Protected,

        [Parameter()]
        [scriptblock]$ReportProgress
    )

    $removed     = [System.Collections.Generic.List[string]]::new()
    $skipped     = [System.Collections.Generic.List[object]]::new()
    $failed      = [System.Collections.Generic.List[object]]::new()
    $localNot    = [System.Collections.Generic.List[string]]::new()
    $sidsToPurge = [System.Collections.Generic.List[string]]::new()

    $report = {
        param([int]$Percent, [string]$Status, [string]$Operation)
        if ($ReportProgress) {
            try { & $ReportProgress @{ PercentComplete = $Percent; Status = $Status; CurrentOperation = $Operation } } catch { }
        }
    }

    # Well-known SIDs that are never user profiles, regardless of mode. S-1-5-18/19/20 are
    # LocalSystem, LocalService and NetworkService. Anything that is not an S-1-5-21 domain
    # or machine account SID is not a person's profile.
    $isUserSid = { param([string]$Sid) $Sid -match '^S-1-5-21-[\d-]+$' }

    # Directory names that are structural rather than personal.
    $excludedNames = @('Administrator', 'Guest', 'DefaultUser', 'Default', 'Default User', 'Public', 'All Users')

    # ---- 1. Enumerate candidate profiles ----------------------------------
    & $report 0 'Enumerating profiles' $Context.Description

    $candidates = [System.Collections.Generic.List[object]]::new()

    if ($Context.IsOffline) {
        # Offline: the ProfileList hive is the authoritative record. Reading the Users
        # directory instead would miss profiles stored elsewhere and would invent
        # candidates for stray directories that are not profiles at all.
        $hiveResult = Invoke-WithRegistryHive -Context $Context -Hive SOFTWARE -ScriptBlock {
            param($root)

            $profileListPath = Join-Path $root 'Microsoft\Windows NT\CurrentVersion\ProfileList'
            if (-not (Test-Path -LiteralPath $profileListPath)) { return @() }

            Get-ChildItem -LiteralPath $profileListPath -ErrorAction SilentlyContinue | ForEach-Object {
                $sid = $_.PSChildName
                $imagePath = (Get-ItemProperty -LiteralPath $_.PSPath -Name 'ProfileImagePath' -ErrorAction SilentlyContinue).ProfileImagePath
                [PSCustomObject]@{ Sid = $sid; ProfileImagePath = $imagePath }
            }
        }

        if (-not $hiveResult.Success) {
            Write-OperationLog -Message "Could not read the offline ProfileList: $($hiveResult.Message)" -LogLevel 'ERROR'
            return [PSCustomObject]@{
                Removed                 = [string[]]@()
                Skipped                 = @()
                Failed                  = @([PSCustomObject]@{ Name = '(enumeration)'; Sid = $null; Reason = $hiveResult.Message })
                LocalAccountsNotRemoved = [string[]]@()
                Complete                = $false
            }
        }

        foreach ($entry in @($hiveResult.Result)) {
            if (-not $entry.ProfileImagePath) { continue }
            if (-not (& $isUserSid $entry.Sid)) { continue }

            $leaf = Split-Path $entry.ProfileImagePath -Leaf
            if ($leaf -in $excludedNames) { continue }

            # ProfileImagePath is recorded relative to the target's own drive letter
            # (usually C:), which is not necessarily the letter that volume has when
            # mounted under WinPE. Rebase onto the context root.
            $rebased = Join-Path $Context.Root ($entry.ProfileImagePath -replace '^[A-Za-z]:\\', '')

            $candidates.Add([PSCustomObject]@{
                Sid       = $entry.Sid
                Name      = $leaf
                LocalPath = $rebased
            })
        }
    }
    else {
        Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
            -not $_.Special -and
            $null -ne $_.LocalPath -and
            (& $isUserSid $_.SID) -and
            (Split-Path $_.LocalPath -Leaf) -notin $excludedNames
        } | ForEach-Object {
            $candidates.Add([PSCustomObject]@{
                Sid       = $_.SID
                Name      = (Split-Path $_.LocalPath -Leaf)
                LocalPath = $_.LocalPath
            })
        }
    }

    if ($candidates.Count -eq 0) {
        Write-OperationLog -Message 'No user profiles found to remove.' -LogLevel 'INFO'
        return [PSCustomObject]@{
            Removed                 = [string[]]@()
            Skipped                 = @()
            Failed                  = @()
            LocalAccountsNotRemoved = [string[]]@()
            Complete                = $true
        }
    }

    # ---- 2. Partition into targets and protected skips ---------------------
    $targets = [System.Collections.Generic.List[object]]::new()

    foreach ($candidate in $candidates) {
        if ($candidate.Sid -in $Protected.Sids -or $candidate.Name -in $Protected.Names) {
            $reason = $Protected.Reasons[$candidate.Sid]
            if (-not $reason) { $reason = 'Account has an active session on this machine.' }

            $skipped.Add([PSCustomObject]@{ Name = $candidate.Name; Sid = $candidate.Sid; Reason = $reason })
            Write-OperationLog -Message "Skipping protected profile '$($candidate.Name)': $reason" -LogLevel 'WARNING'
            continue
        }

        $targets.Add($candidate)
    }

    # ---- 3. Stop processes owned by the targets, live mode only -----------
    # Offline profiles have no processes. Live mode kills only the accounts that survived
    # the protection filter, which is what stops the wipe terminating its own host.
    if (-not $Context.IsOffline -and $targets.Count -gt 0) {
        & $report 5 'Stopping user processes' 'Live session cleanup'

        if ($PSCmdlet.ShouldProcess('Processes owned by targeted profiles', 'Stop')) {
            $targetNames = $targets | ForEach-Object { $_.Name }

            try {
                Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object {
                    if (-not $_.UserName) { return }

                    $procUser = ($_.UserName -split '\\')[-1]
                    if ($procUser -in $Protected.Names) { return }

                    if ($procUser -in $targetNames) {
                        try { $_ | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
                    }
                }

                Write-OperationLog -Message "Stopped processes for: $($targetNames -join ', ')" -LogLevel 'INFO'
            }
            catch {
                Write-OperationLog -Message "Warning stopping user processes: $($_.Exception.Message)" -LogLevel 'WARNING'
            }
        }
    }

    # ---- 4. Remove each targeted profile -----------------------------------
    $index = 0
    foreach ($target in $targets) {
        $index++
        $percent = 10 + [int](($index / [math]::Max($targets.Count, 1)) * 80)
        & $report $percent "Removing profile $index of $($targets.Count)" $target.Name

        if (-not $PSCmdlet.ShouldProcess("User profile: $($target.Name) ($($target.LocalPath))", 'Remove')) {
            $skipped.Add([PSCustomObject]@{ Name = $target.Name; Sid = $target.Sid; Reason = 'Declined at confirmation prompt.' })
            continue
        }

        Write-OperationLog -Message "Removing user profile: $($target.Name) (SID: $($target.Sid))" -LogLevel 'INFO'
        $profileFailed = $null

        try {
            # 4a. Loaded hive, live mode only. Offline hives are files inside the
            # profile directory and go with it in step 4b.
            if (-not $Context.IsOffline) {
                $hivePath = "Registry::HKEY_USERS\$($target.Sid)"
                if (Test-Path $hivePath) {
                    Remove-Item $hivePath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            # 4b. Profile directory
            if (Test-Path -LiteralPath $target.LocalPath) {
                if (-not $Context.IsOffline) {
                    # Ownership is only an obstacle on a running system. Offline, the
                    # WinPE session is already SYSTEM and the ACLs do not apply.
                    & takeown.exe /f "$($target.LocalPath)" /r /d y 2>&1 | Out-Null
                    & icacls.exe "$($target.LocalPath)" /grant administrators:F /t /c /q 2>&1 | Out-Null
                }

                Remove-Item -LiteralPath $target.LocalPath -Recurse -Force -ErrorAction Stop

                if (Test-Path -LiteralPath $target.LocalPath) {
                    $profileFailed = "Profile directory still present after removal: $($target.LocalPath)"
                }
            }

            # 4c. ProfileList record is not removed here. The SIDs are collected and
            # purged in one hive session after the loop, so an offline run mounts and
            # unloads SOFTWARE once instead of once per profile. Every mount cycle is a
            # chance to leak a mount that holds the target volume open.
            $sidsToPurge.Add($target.Sid)

            # 4d. Local account, live mode only
            if ($Context.IsOffline) {
                $localNot.Add($target.Name)
            }
            else {
                try {
                    if (Get-LocalUser -Name $target.Name -ErrorAction SilentlyContinue) {
                        Remove-LocalUser -Name $target.Name -ErrorAction Stop
                        Write-OperationLog -Message "Removed local user account: $($target.Name)" -LogLevel 'INFO'
                    }
                }
                catch {
                    # A domain account has no local entry, which is the expected case on a
                    # machine being reissued. Not a failure.
                    Write-OperationLog -Message "No local account removed for '$($target.Name)' (domain account, or removal refused): $($_.Exception.Message)" -LogLevel 'INFO'
                }
            }

            if ($profileFailed) {
                $failed.Add([PSCustomObject]@{ Name = $target.Name; Sid = $target.Sid; Reason = $profileFailed })
                Write-OperationLog -Message $profileFailed -LogLevel 'ERROR'
            }
            else {
                $removed.Add($target.Name)
            }
        }
        catch {
            $reason = $_.Exception.Message
            $failed.Add([PSCustomObject]@{ Name = $target.Name; Sid = $target.Sid; Reason = $reason })
            Write-OperationLog -Message "Error removing profile $($target.Name): $reason" -LogLevel 'ERROR'
        }
    }

    # ---- 5. Purge ProfileList records in one hive session ------------------
    # A profile directory deleted without its ProfileList record leaves the account's SID
    # and its old profile path readable in the registry, which is exactly the "remnant of
    # a previous user" this wipe exists to remove.
    if ($sidsToPurge.Count -gt 0 -and $PSCmdlet.ShouldProcess("$($sidsToPurge.Count) ProfileList record(s)", 'Remove')) {
        $purge = Invoke-WithRegistryHive -Context $Context -Hive SOFTWARE -ScriptBlock {
            param($root)

            $profileListPath = Join-Path $root 'Microsoft\Windows NT\CurrentVersion\ProfileList'
            $purged = 0

            foreach ($sid in $sidsToPurge) {
                $key = Join-Path $profileListPath $sid
                if (Test-Path -LiteralPath $key) {
                    Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
                    if (-not (Test-Path -LiteralPath $key)) { $purged++ }
                }
                else {
                    # Already absent counts as purged: the end state is what matters.
                    $purged++
                }
            }

            $purged
        }

        if ($purge.Success) {
            Write-OperationLog -Message "Purged $($purge.Result) of $($sidsToPurge.Count) ProfileList record(s)." -LogLevel 'INFO'

            if ($purge.Result -lt $sidsToPurge.Count) {
                $stranded = $sidsToPurge.Count - $purge.Result
                $failed.Add([PSCustomObject]@{
                    Name   = '(ProfileList)'
                    Sid    = $null
                    Reason = "$stranded ProfileList record(s) could not be removed. Previous user SIDs remain in the registry."
                })
            }
        }
        else {
            $failed.Add([PSCustomObject]@{
                Name   = '(ProfileList)'
                Sid    = $null
                Reason = "ProfileList purge failed: $($purge.Message)"
            })
            Write-OperationLog -Message "ProfileList purge failed: $($purge.Message)" -LogLevel 'ERROR'
        }
    }

    & $report 100 'Profile removal complete' "$($removed.Count) removed, $($skipped.Count) skipped, $($failed.Count) failed"

    [PSCustomObject]@{
        Removed                 = [string[]]$removed.ToArray()
        Skipped                 = $skipped.ToArray()
        Failed                  = $failed.ToArray()
        LocalAccountsNotRemoved = [string[]]$localNot.ToArray()
        Complete                = ($skipped.Count -eq 0 -and $failed.Count -eq 0)
    }
}

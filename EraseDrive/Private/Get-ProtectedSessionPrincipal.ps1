function Get-ProtectedSessionPrincipal {
    <#
    .SYNOPSIS
        Identifies the accounts that must not be wiped out from under a live operation.

    .DESCRIPTION
        Defect D1: Invoke-ForensicUserDataWipe selects every non-special profile except
        Administrator, Guest, DefaultUser, Default and Public, then force-kills every
        process owned by those accounts. An operator signed in as anything else, which is
        the normal case for a domain-joined estate, is in that set. The function therefore
        kills its own PowerShell host part way through the wipe, and cannot delete the
        profile directory it is executing from in any case.

        This function returns the principals a live wipe must leave alone:

            - The identity running the current process.
            - Every account with a loaded user hive under HKEY_USERS, which is how a
              running system reports "this profile is in use right now". This catches
              other signed-in sessions, fast-user-switched sessions, and RDP sessions
              that a naive enumeration would happily target.

        In offline mode nobody is signed in, every hive is a file, and the correct answer
        is an empty exclusion set. Returning empty rather than skipping the call keeps the
        caller free of mode branching, and is the reason a WinPE wipe is the only one that
        can be complete.

    .PARAMETER Context
        The target context from Get-TargetContext.

    .OUTPUTS
        PSCustomObject:
            Sids    [string[]] - SIDs that must not be targeted
            Names   [string[]] - Account names that must not be targeted
            Reasons [hashtable] - SID to human-readable reason, for the operator report
            IsEmpty [bool]     - True when nothing needs protecting (offline mode)

    .EXAMPLE
        $protected = Get-ProtectedSessionPrincipal -Context $ctx
        if ($profile.SID -in $protected.Sids) { continue }

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $sids    = [System.Collections.Generic.List[string]]::new()
    $names   = [System.Collections.Generic.List[string]]::new()
    $reasons = @{}

    # ---- Offline: nothing is running, so nothing needs protecting ---------
    if ($Context.IsOffline) {
        return [PSCustomObject]@{
            Sids    = [string[]]@()
            Names   = [string[]]@()
            Reasons = $reasons
            IsEmpty = $true
        }
    }

    # ---- The identity running this process ---------------------------------
    try {
        $current    = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentSid = $current.User.Value
        $currentName = ($current.Name -split '\\')[-1]

        $sids.Add($currentSid)
        $names.Add($currentName)
        $reasons[$currentSid] = "Operator running this wipe ($($current.Name)). Its processes cannot be killed and its profile cannot be deleted while in use."
    }
    catch {
        Write-OperationLog -Message "Could not resolve the current operator identity: $($_.Exception.Message)" -LogLevel 'WARNING'
    }

    # ---- Every account with a loaded hive is signed in somewhere -----------
    # A loaded HKEY_USERS subkey is the running system's own statement that the profile
    # is in use. Classic SIDs only (S-1-5-21-...), and the _Classes companion keys are
    # skipped because they are the same principal.
    try {
        Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop |
            Select-Object -ExpandProperty PSChildName |
            Where-Object { $_ -match '^S-1-5-21-[\d-]+$' } |
            ForEach-Object {
                $loadedSid = $_
                if ($loadedSid -notin $sids) {
                    $sids.Add($loadedSid)
                    $reasons[$loadedSid] = 'Profile hive is loaded, so this account has an active session on this machine.'

                    # Best-effort name resolution. A SID with no resolvable name is still
                    # protected: the SID is what the exclusion is actually keyed on.
                    try {
                        $account = (New-Object System.Security.Principal.SecurityIdentifier($loadedSid)).Translate([System.Security.Principal.NTAccount]).Value
                        $shortName = ($account -split '\\')[-1]
                        if ($shortName -and $shortName -notin $names) {
                            $names.Add($shortName)
                        }
                    }
                    catch { }
                }
            }
    }
    catch {
        Write-OperationLog -Message "Could not enumerate loaded user hives: $($_.Exception.Message)" -LogLevel 'WARNING'
    }

    [PSCustomObject]@{
        Sids    = [string[]]$sids.ToArray()
        Names   = [string[]]$names.ToArray()
        Reasons = $reasons
        IsEmpty = ($sids.Count -eq 0)
    }
}

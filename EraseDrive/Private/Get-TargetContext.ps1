function Get-TargetContext {
    <#
    .SYNOPSIS
        Resolves the Windows installation being operated on, live or offline.

    .DESCRIPTION
        Every remnant-removal primitive in the reissue wipe takes its paths from this
        function rather than from $env: variables. That is what allows one implementation
        to serve both modes:

            Live mode    - the running Windows install. Root is $env:SystemDrive.
            Offline mode - a Windows install mounted from WinPE. Root is the caller's
                           -OfflineRoot, for example 'C:\' as seen from the WinPE RAM disk.

        Offline mode is validated, not assumed. A root that does not contain a registry
        hive set is rejected, and a root that resolves to the currently running Windows
        install is rejected outright: an "offline" operation against the live OS would
        silently do the wrong thing (locked hives, a running operator profile, and a
        caller that believes none of that applies).

    .PARAMETER OfflineRoot
        Path to the root of an offline Windows volume, for example 'C:\' or 'D:\'.
        Omit for live mode.

    .OUTPUTS
        PSCustomObject:
            Valid          [bool]   - Whether the context is usable.
            Reason         [string] - Why it is not usable, when Valid is false.
            IsOffline      [bool]
            Root           [string] - Volume root, always with a trailing separator.
            WindowsDir     [string] - <Root>Windows
            UsersDir       [string] - <Root>Users
            ProgramDataDir [string] - <Root>ProgramData
            ConfigDir      [string] - <Root>Windows\System32\config
            SoftwareHive   [string] - Path to the SOFTWARE hive file
            SystemHive     [string] - Path to the SYSTEM hive file
            SamHive        [string] - Path to the SAM hive file
            SecurityHive   [string] - Path to the SECURITY hive file
            DefaultHive    [string] - Path to the DEFAULT hive file
            Description    [string] - Human-readable summary for logs and certificates

    .EXAMPLE
        $ctx = Get-TargetContext
        Resolves the running Windows install.

    .EXAMPLE
        $ctx = Get-TargetContext -OfflineRoot 'C:\'
        From WinPE, resolves the offline Windows install on C:.

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OfflineRoot
    )

    $fail = {
        param([string]$Why)
        [PSCustomObject]@{
            Valid          = $false
            Reason         = $Why
            IsOffline      = [bool]$OfflineRoot
            Root           = $null
            WindowsDir     = $null
            UsersDir       = $null
            ProgramDataDir = $null
            ConfigDir      = $null
            SoftwareHive   = $null
            SystemHive     = $null
            SamHive        = $null
            SecurityHive   = $null
            DefaultHive    = $null
            Description    = $null
        }
    }

    $isOffline = -not [string]::IsNullOrWhiteSpace($OfflineRoot)

    # ---- Resolve the root -------------------------------------------------
    if ($isOffline) {
        try {
            $resolved = (Resolve-Path -LiteralPath $OfflineRoot -ErrorAction Stop).Path
        }
        catch {
            return & $fail "Offline root '$OfflineRoot' does not exist or is not accessible."
        }
    }
    else {
        $resolved = $env:SystemDrive
    }

    if ([string]::IsNullOrWhiteSpace($resolved)) {
        return & $fail 'Could not determine the target volume root.'
    }

    # Normalise to a trailing separator so every Join-Path below behaves the same
    $root = $resolved.TrimEnd('\', '/') + '\'

    $windowsDir = Join-Path $root 'Windows'
    $configDir  = Join-Path $windowsDir 'System32\config'

    # ---- Offline mode must not be pointed at the running OS ---------------
    # This is checked FIRST, before any validation that could fail for an unrelated
    # reason. Ordering matters: the registry hives below are ACL-denied on a running
    # system, so a hive check placed ahead of this guard would reject the live OS with
    # the wrong reason and the guard would never be reached at all. A safety check that
    # is short-circuited by an earlier failure is not a safety check.
    if ($isOffline) {
        $liveWindows = $env:SystemRoot
        if ($liveWindows) {
            $liveNorm   = $liveWindows.TrimEnd('\', '/').ToLowerInvariant()
            $targetNorm = $windowsDir.TrimEnd('\', '/').ToLowerInvariant()

            if ($liveNorm -eq $targetNorm) {
                return & $fail (
                    "Offline root '$root' resolves to the currently running Windows installation " +
                    "('$liveWindows'). Offline mode requires a Windows install that is not booted. " +
                    'Boot the EraseDrive WinPE media and target the internal volume, or use live mode.'
                )
            }
        }
    }

    # ---- Validate that this is actually a Windows installation ------------
    # The registry hive set is the authoritative tell. A Users directory is not:
    # a data volume can have one, and a freshly imaged install may not yet.
    $softwareHive = Join-Path $configDir 'SOFTWARE'
    $systemHive   = Join-Path $configDir 'SYSTEM'

    # "Access denied" and "not there" are different states and must not share a
    # representation. Test-Path throws UnauthorizedAccessException on the live hive
    # files, which are ACL-locked to SYSTEM; treating that as absence would report a
    # perfectly good Windows installation as not being one. A path we are refused
    # access to demonstrably exists.
    $pathPresent = {
        param([string]$Candidate)
        try {
            return [bool](Test-Path -LiteralPath $Candidate -ErrorAction Stop)
        }
        catch {
            # Walk the exception chain rather than matching one type: the provider wraps
            # the access denial differently across PowerShell versions, and a typed catch
            # that silently stops matching would reintroduce the exact confusion this
            # guards against.
            $ex = $_.Exception
            while ($ex) {
                if ($ex -is [System.UnauthorizedAccessException]) { return $true }
                $ex = $ex.InnerException
            }
            return $false
        }
    }

    if (-not (& $pathPresent $windowsDir)) {
        return & $fail "No Windows directory at '$windowsDir'. This is not a Windows installation."
    }

    if (-not (& $pathPresent $softwareHive) -or -not (& $pathPresent $systemHive)) {
        return & $fail "Registry hives not found under '$configDir'. This is not a usable Windows installation."
    }

    # ---- Build the context ------------------------------------------------
    $description = if ($isOffline) {
        "Offline Windows installation at $root"
    }
    else {
        "Live Windows installation at $root ($env:COMPUTERNAME)"
    }

    [PSCustomObject]@{
        Valid          = $true
        Reason         = $null
        IsOffline      = $isOffline
        Root           = $root
        WindowsDir     = $windowsDir
        UsersDir       = Join-Path $root 'Users'
        ProgramDataDir = Join-Path $root 'ProgramData'
        ConfigDir      = $configDir
        SoftwareHive   = $softwareHive
        SystemHive     = $systemHive
        SamHive        = Join-Path $configDir 'SAM'
        SecurityHive   = Join-Path $configDir 'SECURITY'
        DefaultHive    = Join-Path $configDir 'DEFAULT'
        Description    = $description
    }
}

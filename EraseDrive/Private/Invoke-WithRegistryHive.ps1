function Invoke-WithRegistryHive {
    <#
    .SYNOPSIS
        Runs a scriptblock against a registry hive, mounting it first when the target is offline.

    .DESCRIPTION
        This is the abstraction that lets a single primitive serve both live and WinPE
        modes without branching on which one it is in.

        Live mode    - hands the scriptblock the well-known live path, e.g. 'HKLM:\SOFTWARE'.
                       Nothing is mounted and nothing is unmounted.
        Offline mode - loads the hive file from the offline Windows install under a
                       unique temporary key, hands the scriptblock that path, and
                       guarantees the hive is unloaded again.

        The scriptblock therefore only ever deals in "here is a registry path, operate on
        it". It never learns which mode it is in, which means there is no second code path
        to keep correct.

        Unload reliability is handled here, not left to callers. The .NET registry provider
        keeps handles alive after a key is touched, and 'reg unload' fails with
        "Access is denied" while any remain. Garbage collection is forced and the unload is
        retried before the failure is reported. A hive that will not unload is reported as a
        failure rather than swallowed, because a leaked mount blocks later operations and
        can hold the target volume open.

    .PARAMETER Context
        The target context from Get-TargetContext.

    .PARAMETER Hive
        Which hive to operate on: SOFTWARE, SYSTEM, SAM, SECURITY, or DEFAULT.

    .PARAMETER ScriptBlock
        Receives one argument: the registry path to operate on, in PowerShell provider
        form (for example 'HKLM:\SOFTWARE' or 'HKLM:\ED_SOFTWARE_3f2a').

    .OUTPUTS
        PSCustomObject:
            Success  [bool]   - Whether the hive was made available and the block ran.
            Mounted  [bool]   - Whether a hive was actually mounted (offline mode only).
            Unloaded [bool]   - Whether the mount was cleanly released.
            Result   [object] - Whatever the scriptblock returned.
            Message  [string] - Failure detail when Success is false.

    .EXAMPLE
        Invoke-WithRegistryHive -Context $ctx -Hive SOFTWARE -ScriptBlock {
            param($root)
            Get-ChildItem "$root\Microsoft\Windows NT\CurrentVersion\ProfileList"
        }

    .NOTES
        Private helper. Module: EraseDrive
        Requires SeRestorePrivilege (administrator) for offline mounts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter(Mandatory)]
        [ValidateSet('SOFTWARE', 'SYSTEM', 'SAM', 'SECURITY', 'DEFAULT')]
        [string]$Hive,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock
    )

    # ---- Live mode: no mounting required ----------------------------------
    if (-not $Context.IsOffline) {
        # SAM, SECURITY, SOFTWARE, SYSTEM all hang off HKLM in a running system.
        # DEFAULT is the .DEFAULT user hive, which lives under HKEY_USERS.
        $livePath = if ($Hive -eq 'DEFAULT') { 'Registry::HKEY_USERS\.DEFAULT' } else { "HKLM:\$Hive" }

        try {
            $result = & $ScriptBlock $livePath
            return [PSCustomObject]@{
                Success  = $true
                Mounted  = $false
                Unloaded = $true
                Result   = $result
                Message  = $null
            }
        }
        catch {
            return [PSCustomObject]@{
                Success  = $false
                Mounted  = $false
                Unloaded = $true
                Result   = $null
                Message  = "Scriptblock failed against live hive '$Hive': $($_.Exception.Message)"
            }
        }
    }

    # ---- Offline mode: mount, run, guarantee unload ------------------------
    $hiveFile = switch ($Hive) {
        'SOFTWARE' { $Context.SoftwareHive }
        'SYSTEM'   { $Context.SystemHive }
        'SAM'      { $Context.SamHive }
        'SECURITY' { $Context.SecurityHive }
        'DEFAULT'  { $Context.DefaultHive }
    }

    if (-not (Test-Path -LiteralPath $hiveFile)) {
        return [PSCustomObject]@{
            Success  = $false
            Mounted  = $false
            Unloaded = $true
            Result   = $null
            Message  = "Hive file not found: $hiveFile"
        }
    }

    # Unique mount name so concurrent or retried operations cannot collide
    $mountName = "ED_${Hive}_" + ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $mountKey  = "HKLM\$mountName"
    $mountPath = "HKLM:\$mountName"
    $mounted   = $false
    $unloaded  = $false

    # The outcome is built into a variable rather than returned from inside the try,
    # so that the finally block can record whether the unload actually succeeded.
    # Returning directly would emit the object before the unload is attempted, and
    # a failed unload would then be reported as a clean one.
    $outcome = $null

    try {
        $loadOutput = & reg.exe load $mountKey "$hiveFile" 2>&1
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{
                Success  = $false
                Mounted  = $false
                Unloaded = $true
                Result   = $null
                Message  = "Failed to load hive '$hiveFile' as '$mountKey': $loadOutput"
            }
        }

        $mounted = $true
        Write-OperationLog -Message "Mounted offline hive $Hive from $hiveFile as $mountKey" -LogLevel 'INFO'

        $result = & $ScriptBlock $mountPath

        $outcome = [PSCustomObject]@{
            Success  = $true
            Mounted  = $true
            Unloaded = $false
            Result   = $result
            Message  = $null
        }
    }
    catch {
        $outcome = [PSCustomObject]@{
            Success  = $false
            Mounted  = $mounted
            Unloaded = $false
            Result   = $null
            Message  = "Scriptblock failed against offline hive '$Hive': $($_.Exception.Message)"
        }
    }
    finally {
        if ($mounted) {
            # The registry provider holds handles open after any key is touched.
            # Force collection before unloading, then retry: a first-attempt failure
            # here is normal, not exceptional.
            $unloaded = $false
            for ($attempt = 1; $attempt -le 5 -and -not $unloaded; $attempt++) {
                [gc]::Collect()
                [gc]::WaitForPendingFinalizers()

                $unloadOutput = & reg.exe unload $mountKey 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $unloaded = $true
                    Write-OperationLog -Message "Unloaded offline hive $mountKey (attempt $attempt)" -LogLevel 'INFO'
                }
                elseif ($attempt -lt 5) {
                    Start-Sleep -Milliseconds (200 * $attempt)
                }
                else {
                    # Surfaced loudly: a leaked mount holds the volume open and will
                    # break any later operation that expects exclusive access.
                    Write-OperationLog -Message "Failed to unload offline hive $mountKey after $attempt attempts: $unloadOutput" -LogLevel 'ERROR'
                }
            }

            if ($outcome) {
                $outcome.Unloaded = $unloaded

                # A leaked mount is a failure of the operation even when the scriptblock
                # itself succeeded. Callers must not treat this as a clean result.
                if (-not $unloaded) {
                    $outcome.Success = $false
                    $outcome.Message = "Hive '$Hive' was mounted as '$mountKey' and could not be unloaded. The mount is still present and the target volume is still held open."
                }
            }
        }
    }

    $outcome
}

function Clear-RecycleBinAllVolume {
    <#
    .SYNOPSIS
        Empties the Recycle Bin on every volume, not just the system volume.

    .DESCRIPTION
        Each volume carries its own $Recycle.Bin directory, containing a per-SID subfolder
        for every user who has ever deleted a file on that volume. Deleting a user profile
        from C: does nothing to the files that user deleted from D:, and the per-SID folder
        name preserves the account SID as well.

        Emptying only the system volume is the common mistake, and on a machine with a
        secondary data drive it leaves the largest and most business-relevant collection
        of deleted company files completely intact.

        Live mode covers every fixed volume on the machine. Offline mode covers the volume
        it was given; a device with more than one volume needs one call per volume, which
        the orchestrator handles.

    .PARAMETER Context
        Target context from Get-TargetContext.

    .OUTPUTS
        PSCustomObject: Name, Success, ItemsRemoved, VolumesProcessed, Warnings, Message

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $warnings = [System.Collections.Generic.List[string]]::new()
    $removed  = 0
    $success  = $true

    # ---- Decide which volume roots are in scope ---------------------------
    $roots = [System.Collections.Generic.List[string]]::new()

    if ($Context.IsOffline) {
        $roots.Add($Context.Root)
    }
    else {
        try {
            Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' -ErrorAction Stop |
                ForEach-Object { $roots.Add(($_.DeviceID.TrimEnd('\') + '\')) }
        }
        catch {
            $warnings.Add("Could not enumerate fixed volumes, falling back to the system volume only: $($_.Exception.Message)")
            $roots.Add($Context.Root)
        }
    }

    if (-not $PSCmdlet.ShouldProcess(($roots -join ', '), 'Empty Recycle Bin')) {
        return [PSCustomObject]@{
            Name = 'RecycleBin'; Success = $true; ItemsRemoved = 0; VolumesProcessed = 0
            Warnings = @(); Message = 'Declined at confirmation prompt.'
        }
    }

    foreach ($root in $roots) {
        $binPath = Join-Path $root '$Recycle.Bin'

        if (-not (Test-Path -LiteralPath $binPath)) {
            continue
        }

        try {
            # Each child is a per-SID folder. Removing the children rather than the
            # $Recycle.Bin directory itself keeps Windows from having to recreate a
            # structure it expects to exist.
            $sidFolders = @(Get-ChildItem -LiteralPath $binPath -Force -ErrorAction SilentlyContinue)

            foreach ($folder in $sidFolders) {
                try {
                    Remove-Item -LiteralPath $folder.FullName -Recurse -Force -ErrorAction Stop
                    $removed++
                }
                catch {
                    # The currently signed-in user's bin folder is in use during a live
                    # run. That is expected and is covered by the profile removal step.
                    $warnings.Add("Could not remove '$($folder.FullName)': $($_.Exception.Message)")
                }
            }

            Write-OperationLog -Message "Emptied Recycle Bin on $root ($($sidFolders.Count) per-user folder(s) found)" -LogLevel 'INFO'
        }
        catch {
            $success = $false
            $warnings.Add("Could not process the Recycle Bin on '$root': $($_.Exception.Message)")
        }
    }

    [PSCustomObject]@{
        Name             = 'RecycleBin'
        Success          = $success
        ItemsRemoved     = $removed
        VolumesProcessed = $roots.Count
        Warnings         = $warnings.ToArray()
        Message          = "Removed $removed per-user Recycle Bin folder(s) across $($roots.Count) volume(s)."
    }
}

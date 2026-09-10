function Test-DiskSafeToErase {
    <#
    .SYNOPSIS
        Evaluates whether a disk is safe for complete erasure.

    .DESCRIPTION
        Performs a series of safety checks against the specified disk to determine
        if it can be safely erased without risking the operating system or boot
        environment. Checks include:

        - System disk detection (IsSystem flag)
        - Boot disk detection (IsBoot flag)
        - Health status validation
        - System/Reserved/Recovery partition detection
        - Windows installation or Program Files presence on any mounted partition
        - EraseDrive's own volume: refuses to erase the disk the module is running
          from, or the disk holding the current working directory
        - Large disk (>2TB) advisory warning

        Returns a structured PSCustomObject with Safe (boolean) and Reason (string)
        properties instead of the legacy tuple/array return pattern.

        Uses Get-CimInstance for WMI queries instead of the deprecated Get-WmiObject.

    .PARAMETER DiskNumber
        The disk number to evaluate (as shown by Get-Disk).

    .EXAMPLE
        $result = Test-DiskSafeToErase -DiskNumber 1
        if ($result.Safe) { Write-Host 'Disk is safe to erase' }

    .EXAMPLE
        Test-DiskSafeToErase -DiskNumber 0
        # Returns: @{ Safe = $false; Reason = 'This is the system disk containing the operating system.' }

    .OUTPUTS
        PSCustomObject with properties:
            Safe   [bool]   - Whether the disk is safe to erase.
            Reason [string] - Human-readable explanation of the safety determination.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$DiskNumber
    )

    try {
        $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop

        # Check if disk is offline
        if ($disk.OperationalStatus -eq 'Offline') {
            return [PSCustomObject]@{
                Safe   = $false
                Reason = 'Disk is offline. Bring it online first to verify contents.'
            }
        }

        # Check if disk is part of a Storage Space or RAID
        $storagePool = Get-VirtualDisk -ErrorAction SilentlyContinue | ForEach-Object {
            $vd = $_
            Get-PhysicalDisk -VirtualDisk $vd -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq "$DiskNumber" }
        }
        if ($storagePool) {
            return [PSCustomObject]@{
                Safe   = $false
                Reason = 'Disk is part of a Storage Space or RAID array.'
            }
        }

        # Check if this is the system disk
        if ($disk.IsSystem) {
            return [PSCustomObject]@{
                Safe   = $false
                Reason = 'This is the system disk containing the operating system.'
            }
        }

        # Check if this is the boot disk
        if ($disk.IsBoot) {
            return [PSCustomObject]@{
                Safe   = $false
                Reason = 'This is the boot disk.'
            }
        }

        # Check disk health status
        if ($disk.HealthStatus -ne 'Healthy') {
            return [PSCustomObject]@{
                Safe   = $false
                Reason = "Disk health is '$($disk.HealthStatus)' - may indicate hardware issues."
            }
        }

        # Check for system, reserved, or recovery partitions
        $partitions = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue
        foreach ($partition in $partitions) {
            if ($partition.Type -eq 'System' -or $partition.Type -eq 'Reserved' -or $partition.Type -eq 'Recovery') {
                return [PSCustomObject]@{
                    Safe   = $false
                    Reason = 'This disk contains system, reserved, or recovery partitions.'
                }
            }

            # Check mounted partitions for Windows installation or Program Files
            if ($partition.DriveLetter) {
                $windowsPath = "$($partition.DriveLetter):\Windows"
                $programFilesPath = "$($partition.DriveLetter):\Program Files"
                if ((Test-Path $windowsPath) -or (Test-Path $programFilesPath)) {
                    return [PSCustomObject]@{
                        Safe   = $false
                        Reason = 'This disk contains a Windows installation or program files.'
                    }
                }
            }
        }

        # Check if disk is a virtual disk (Hyper-V pass-through, etc.)
        $physDisk = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq "$DiskNumber" }
        $virtualDiskWarning = ''
        if ($physDisk -and $physDisk.BusType -eq 'Virtual') {
            # Could be a Hyper-V pass-through or virtual disk - warn but allow
            $virtualDiskWarning = ' WARNING: Virtual disk detected - verify this is not backing critical VMs.'
        }

        # ── Refuse to erase the disk EraseDrive is running from ─────────
        #
        # None of the checks above catch this. A removable disk holding the tool,
        # the operator's data, or the working directory is not the system disk, is
        # not the boot disk, is healthy, and has no \Windows on it, so every
        # preceding test passes it as safe.
        #
        # That is not a hypothetical. The intended deployment runs EraseDrive from
        # a USB stick, and on this fleet the module lives on a portable SSD that
        # also carries every project. Erasing it would destroy the running code
        # part way through the operation, along with everything else on the drive,
        # and the operator would be selecting a plausible-looking non-system disk
        # in the GUI when they did it.
        #
        # Identity here is the DISK NUMBER behind a path's volume, not the path
        # itself, because several drive letters can live on one physical disk.
        $selfPaths = New-Object System.Collections.Generic.List[string]
        foreach ($candidate in @(
                $PSScriptRoot
                $(if ($Script:EraseDriveConfig) { $Script:EraseDriveConfig.ModuleRoot } else { $null })
                $(try { (Get-Location).Path } catch { $null })
            )) {
            if (-not [string]::IsNullOrWhiteSpace($candidate)) { $selfPaths.Add($candidate) }
        }

        $selfCheckFailed = $false
        foreach ($selfPath in $selfPaths) {
            try {
                $qualifier = Split-Path -Qualifier $selfPath -ErrorAction Stop
            }
            catch {
                # UNC path, or a volume with no drive letter. Nothing to compare.
                continue
            }
            if ([string]::IsNullOrWhiteSpace($qualifier)) { continue }

            $letter = $qualifier.TrimEnd(':')
            try {
                $selfPartition = Get-Partition -DriveLetter $letter -ErrorAction Stop
            }
            catch {
                # Could not resolve this letter to a disk. Record it: an
                # undetermined self-check is reported, never silently treated as a
                # pass.
                $selfCheckFailed = $true
                continue
            }

            foreach ($sp in @($selfPartition)) {
                if ($null -ne $sp.DiskNumber -and [int]$sp.DiskNumber -eq $DiskNumber) {
                    return [PSCustomObject]@{
                        Safe   = $false
                        Reason = "This disk holds EraseDrive itself or the current working directory ('$selfPath' is on disk $DiskNumber). Erasing it would destroy the running tool and its data mid-operation."
                    }
                }
            }
        }

        # Build the safe response, with optional large-disk advisory
        $reason = 'Disk appears safe to erase.'
        $sizeGB = [math]::Round($disk.Size / 1GB, 2)
        if ($sizeGB -gt 2048) {
            $reason = "Disk appears safe to erase. WARNING: Large disk detected (${sizeGB} GB > 2 TB) - erase operation may take a very long time."
        }

        $reason += $virtualDiskWarning

        if ($selfCheckFailed) {
            $reason += ' WARNING: could not determine which disk holds EraseDrive itself, so the self-erase check is incomplete. Confirm the target disk manually before proceeding.'
        }

        return [PSCustomObject]@{
            Safe   = $true
            Reason = $reason
        }
    }
    catch {
        return [PSCustomObject]@{
            Safe   = $false
            Reason = "Error accessing disk: $($_.Exception.Message)"
        }
    }
}

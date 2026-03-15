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

        # Build the safe response, with optional large-disk advisory
        $reason = 'Disk appears safe to erase.'
        $sizeGB = [math]::Round($disk.Size / 1GB, 2)
        if ($sizeGB -gt 2048) {
            $reason = "Disk appears safe to erase. WARNING: Large disk detected (${sizeGB} GB > 2 TB) - erase operation may take a very long time."
        }

        $reason += $virtualDiskWarning

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

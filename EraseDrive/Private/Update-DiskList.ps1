function Update-DiskList {
    <#
    .SYNOPSIS
        Populates a DataTable with current disk information for the EraseDrive GUI.

    .DESCRIPTION
        Queries all attached disks and physical disk metadata, then populates the
        provided DataTable with detailed information for each disk. The system disk
        is always listed first with a special safety status.

        Compared to the legacy version, this function adds:
        - SerialNumber column (from Get-PhysicalDisk)
        - MediaType column (SSD/HDD/Unspecified from Get-PhysicalDisk)

        Non-system disks are evaluated via Test-DiskSafeToErase for safety status.

        Uses Get-CimInstance instead of the deprecated Get-WmiObject for all WMI
        queries.

    .PARAMETER Table
        A System.Data.DataTable instance with the expected column schema:
        Number, FriendlyName, SerialNumber, MediaType, BusType, OperationalStatus,
        HealthStatus, 'Size (GB)', Partitions, 'Safety Status'.

    .EXAMPLE
        $table = New-Object System.Data.DataTable
        # ... add columns ...
        Update-DiskList -Table $table

    .OUTPUTS
        None. The DataTable is modified in place.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Data.DataTable]$Table
    )

    $Table.Rows.Clear()

    try {
        $allDisks = Get-Disk -ErrorAction Stop

        # Build a lookup of physical disk info keyed by device ID for serial/media type
        $physicalDisks = @{}
        try {
            Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
                $physicalDisks[$_.DeviceId] = $_
            }
        }
        catch {
            # Physical disk info is supplemental - continue without it
        }

        # Helper: get partition summary string for a disk
$getPartitionInfo = {
    param([int]$diskNum)
    $parts = Get-Partition -DiskNumber $diskNum -ErrorAction SilentlyContinue
    if ($parts) {
        ($parts | ForEach-Object {
            $dl = $(if ($_.DriveLetter) { "$($_.DriveLetter):" } else { 'No Drive' })
            "${dl}($($_.Type))"
        }) -join ', '
    }
    else {
        'Unpartitioned'
    }
}

        # Helper: add a disk row to the table
$addRow = {
    param($disk, [string]$safetyStatus)
    $sizeGB = [math]::Round($disk.Size / 1GB, 2)
    $partitionInfo = & $getPartitionInfo $disk.Number

    # Look up physical disk metadata
    $physDisk = $physicalDisks["$($disk.Number)"]
    $serialNumber = $(if ($physDisk) { $physDisk.SerialNumber } else { 'N/A' })
    $mediaType = $(if ($physDisk) { [string]$physDisk.MediaType } else { 'Unspecified' })

    $row = $Table.NewRow()
    $row['Number']            = $disk.Number
    $row['FriendlyName']      = $disk.FriendlyName
    $row['SerialNumber']      = $serialNumber
    $row['MediaType']         = $mediaType
    $row['BusType']           = $disk.BusType
    $row['OperationalStatus'] = $disk.OperationalStatus
    $row['HealthStatus']      = $disk.HealthStatus
    $row['Size (GB)']         = $sizeGB
    $row['Partitions']        = $partitionInfo
    $row['Safety Status']     = $safetyStatus
    $Table.Rows.Add($row)
}

        # System/boot disks listed first
        $systemDisks = $allDisks | Where-Object { $_.IsSystem -or $_.IsBoot }
        foreach ($sysDisk in $systemDisks) {
            & $addRow $sysDisk 'SYSTEM DISK - User Data Wipe Only'
        }

        # Non-system disks with safety evaluation
        $otherDisks = $allDisks | Where-Object {
            -not $_.IsSystem -and
            -not $_.IsBoot -and
            $_.Size -gt 0
        }

        foreach ($disk in $otherDisks) {
            $safetyCheck = Test-DiskSafeToErase -DiskNumber $disk.Number
            $status = $(if ($safetyCheck.Safe) { 'SAFE' } else { "UNSAFE: $($safetyCheck.Reason)" })
            & $addRow $disk $status
        }
    }
    catch {
        Write-OperationLog -Message "Error retrieving disk information: $($_.Exception.Message)" -LogLevel 'ERROR'
    }
}

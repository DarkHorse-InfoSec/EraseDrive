function Get-DiskMediaType {
    <#
    .SYNOPSIS
        Determines the media type, protocol, and secure erase capabilities of a disk.

    .DESCRIPTION
        Queries Get-PhysicalDisk to identify whether a disk is SSD, HDD, or Unknown,
        and determines its bus protocol (NVMe, SATA, SAS, USB, or Unknown). Based on
        these attributes, the function reports whether the disk supports hardware-level
        secure erase (ATA Secure Erase for SATA SSDs, NVMe Format for NVMe drives)
        and TRIM (via fsutil).

        This information is critical for selecting the optimal erasure method:
        - NVMe SSDs: use NVMe Format command for cryptographic erase
        - SATA SSDs: use ATA Secure Erase for hardware-level wipe
        - HDDs: use multi-pass overwrite (NIST 800-88 compliant)
        - USB/Unknown: fall back to standard overwrite methods

    .PARAMETER DiskNumber
        The disk number to query (as shown by Get-Disk).

    .EXAMPLE
        $info = Get-DiskMediaType -DiskNumber 0
        if ($info.MediaType -eq 'SSD' -and $info.Protocol -eq 'NVMe') {
            Write-Host 'NVMe SSD detected - NVMe Format available'
        }

    .EXAMPLE
        Get-DiskMediaType -DiskNumber 1
        # Returns: @{ MediaType = 'HDD'; SupportsSecureErase = $false; SupportsTrim = $false; Protocol = 'SATA' }

    .OUTPUTS
        PSCustomObject with properties:
            MediaType           [string] - 'SSD', 'HDD', or 'Unknown'
            SupportsSecureErase [bool]   - Whether ATA Secure Erase or NVMe Format is available.
            SupportsTrim        [bool]   - Whether TRIM/Unmap is supported.
            Protocol            [string] - 'NVMe', 'SATA', 'SAS', 'USB', or 'Unknown'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int]$DiskNumber
    )

    # Defaults
    $mediaType = 'Unknown'
    $supportsSecureErase = $false
    $supportsTrim = $false
    $protocol = 'Unknown'

    try {
        # Get physical disk info
        $physDisk = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq "$DiskNumber" }

        if ($physDisk) {
            # Determine media type
            $mediaType = switch ($physDisk.MediaType) {
                'SSD'         { 'SSD' }
                'HDD'         { 'HDD' }
                'Unspecified' { 'Unknown' }
                default       { 'Unknown' }
            }

            # Determine protocol from BusType
            $protocol = switch ($physDisk.BusType) {
                'NVMe'   { 'NVMe' }
                'SATA'   { 'SATA' }
                'ATA'    { 'SATA' }   # ATA is effectively SATA for modern disks
                'SAS'    { 'SAS' }
                'USB'    { 'USB' }
                'RAID'   { 'SATA' }   # RAID controllers typically use SATA/SAS
                default  { 'Unknown' }
            }

            # Determine secure erase support based on media type and protocol
            # NVMe SSDs support NVMe Format (cryptographic erase)
            # SATA SSDs support ATA Secure Erase
            # HDDs and USB devices do not support hardware-level secure erase
            if ($mediaType -eq 'SSD') {
                if ($protocol -eq 'NVMe' -or $protocol -eq 'SATA') {
                    $supportsSecureErase = $true
                }
            }
        }

        # Detect TRIM support via fsutil
        # fsutil behavior query disabledeletenotify returns 0 when TRIM is enabled
        try {
            $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
            if ($disk) {
                $partitions = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue
                $driveWithLetter = $partitions | Where-Object { $_.DriveLetter } | Select-Object -First 1

                if ($driveWithLetter) {
                    $driveLetter = $driveWithLetter.DriveLetter
                    $fsutilOutput = fsutil behavior query disabledeletenotify "$($driveLetter):" 2>&1
                    if ($fsutilOutput -match 'DisableDeleteNotify\s*=\s*0') {
                        $supportsTrim = $true
                    }
                    elseif ($fsutilOutput -match 'NTFS DisableDeleteNotify\s*=\s*0') {
                        $supportsTrim = $true
                    }
                    elseif ($fsutilOutput -match 'ReFS DisableDeleteNotify\s*=\s*0') {
                        $supportsTrim = $true
                    }
                }
                else {
                    # No mounted partition to check - infer from media type
                    if ($mediaType -eq 'SSD') {
                        $supportsTrim = $true
                    }
                }
            }
        }
        catch {
            # TRIM detection is best-effort; infer from media type
            if ($mediaType -eq 'SSD') {
                $supportsTrim = $true
            }
        }
    }
    catch {
        Write-OperationLog -Message "Error detecting media type for disk ${DiskNumber}: $($_.Exception.Message)" -LogLevel 'WARNING'
    }

    return [PSCustomObject]@{
        MediaType           = $mediaType
        SupportsSecureErase = $supportsSecureErase
        SupportsTrim        = $supportsTrim
        Protocol            = $protocol
    }
}

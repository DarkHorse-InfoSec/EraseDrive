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
            SupportsSecureErase [bool?]  - Whether the DEVICE reports a command reaching
                                           NIST Purge. Three-state: $true, $false, or $null
                                           when it could not be determined.
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
    # $null, not $false: absent a query this is UNKNOWN, and saying "false" would
    # be the same unearned claim in the opposite direction.
    $supportsSecureErase = $null
    $sanitizeCapability = $null
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

        }

        # Hardware secure erase support is MEASURED, never inferred.
        #
        # This block previously read: if the media is an SSD and the bus is NVMe or
        # SATA, set SupportsSecureErase to true. That asked the device nothing. It
        # was written into the operation log by Invoke-SecureDiskErase, so a tool
        # whose paid deliverable is a compliance certificate was recording a
        # hardware capability it had never checked, in the audit trail, in a form
        # indistinguishable from a measurement.
        #
        # Get-DiskSanitizeCapability asks the drive. Its answer is three-state, and
        # $null (unknown) is preserved here rather than being flattened to $false,
        # because "we could not determine this" and "this drive cannot do it" are
        # different facts.
        $sanitizeCapability = Get-DiskSanitizeCapability -DiskNumber $DiskNumber
        $supportsSecureErase = $sanitizeCapability.PurgeCapable

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

        # The full capability record, so a caller can report WHY as well as WHAT.
        # Measured 2026-09-10: for a disk number that does not exist this is NOT
        # $null but a record with Determination = 'NotAttempted' and
        # PurgeCapable = $null, because Get-DiskSanitizeCapability always returns
        # a record. It is $null only if an exception reached the catch below.
        SanitizeCapability  = $sanitizeCapability
    }
}

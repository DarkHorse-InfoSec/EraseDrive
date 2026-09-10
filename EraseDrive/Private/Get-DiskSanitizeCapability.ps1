function Get-DiskSanitizeCapability {
    <#
    .SYNOPSIS
        Reports whether a disk can reach NIST SP 800-88 Purge, by ASKING the device.

    .DESCRIPTION
        READ-ONLY capability detection. Phase 1 of the sanitization work: it
        detects and reports, and issues no destructive command.

        This exists because the capability report it replaces was an inference.
        Get-DiskMediaType set SupportsSecureErase to true for any SSD on an NVMe or
        SATA bus without ever asking the drive, and that value was written into the
        operation log of a tool whose paid deliverable is a compliance certificate.
        A guess recorded in an audit trail is worse than no value at all, because
        it is indistinguishable from a measurement.

        THE THREE-STATE RULE. PurgeCapable is deliberately nullable:

            $true   Purge is reachable: the device reported at least one
                    qualifying command and the bus can carry it
            $false  Purge is definitively NOT reachable, either because the
                    device answered and reported no qualifying command, or
                    because the bus cannot carry one at all (USB, virtual)
            $null   UNKNOWN: the device was never asked, the query failed, or
                    the only qualifying commands it reports are ones whose Purge
                    credit depends on a media type that could not be identified

        $null must never collapse to $false. "We could not determine this" and
        "this drive cannot be purged" are different facts, and a certificate that
        confuses them is making a compliance claim it has not earned. This is the
        same class of defect as a sentinel that cannot be distinguished from a
        legitimate zero.

        $false covers two distinct routes to the same operational conclusion, so
        DeviceAnswered records which one applies: $true when the interpretation
        rests on the device's own report, $false when it rests on the bus alone.
        Both are honest answers to "can this disk be purged as it is attached
        right now", which is the question an operator is actually asking, and
        neither can over-claim. An auditor reading the record can still tell a
        drive that said no from a bridge that was never asked.

    .PARAMETER DiskNumber
        Physical disk number.

    .OUTPUTS
        PSCustomObject. Key fields:
            PurgeCapable      [bool?]    three-state, see above
            Determination     [string]   Queried | NotAttempted | QueryFailed
            PurgeMethods      [string[]] commands the device reports
            Blockers          [string[]] reasons Purge cannot proceed now
            EvidenceSummary   [string]   one line fit for a certificate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [int] $DiskNumber
    )

    $busType      = 'Unknown'
    $mediaType    = 'Unknown'
    $friendlyName = $null
    $serialNumber = $null

    try {
        $physical = Get-PhysicalDisk -ErrorAction SilentlyContinue |
                    Where-Object { $_.DeviceId -eq "$DiskNumber" } |
                    Select-Object -First 1
        if ($physical) {
            $busType      = [string] $physical.BusType
            $mediaType    = [string] $physical.MediaType
            $friendlyName = [string] $physical.FriendlyName
            $serialNumber = [string] $physical.SerialNumber
        }
    }
    catch {
        Write-OperationLog -Message "Could not read physical disk information for disk ${DiskNumber}: $($_.Exception.Message)" -LogLevel 'WARNING'
    }

    $result = [ordered]@{
        DiskNumber      = $DiskNumber
        BusType         = $busType
        MediaType       = $mediaType
        FriendlyName    = $friendlyName
        SerialNumber    = $serialNumber
        Protocol        = $null
        Determination   = 'NotAttempted'
        DeviceAnswered  = $false
        PurgeCapable    = $null
        PurgeMethods    = @()
        Blockers        = @()
        SecurityFrozen  = $null
        QueryError      = $null
        Raw             = $null
        EvidenceSummary = $null
    }

    # -----------------------------------------------------------------------
    # Buses that cannot carry a sanitize command at all.
    # -----------------------------------------------------------------------
    # A USB flash drive is not an ATA or NVMe device and has no feature set to
    # address. A USB-SATA enclosure may translate commands via SAT, but does so
    # unreliably and differently per bridge chip. Issuing a sanitize command
    # through one and trusting the return code is how a tool ends up certifying a
    # wipe that never happened, so this refuses by bus type and says so.
    $unsupportedBuses = @{
        'USB'      = 'The disk is attached over USB. A USB bridge does not expose the underlying ATA or NVMe feature set, so no sanitize command can be issued or verified through it.'
        'SD'       = 'SD and MMC media expose no sanitize feature set.'
        'MMC'      = 'SD and MMC media expose no sanitize feature set.'
        '1394'     = 'FireWire bridges do not expose the underlying device feature set.'
        'Virtual'  = 'This is a virtual disk. A virtual disk has no ATA or NVMe feature set to sanitize; Purge is a property of physical media.'
        'File Backed Virtual' = 'This is a file-backed virtual disk and has no physical media to sanitize.'
    }

    if ($unsupportedBuses.ContainsKey($busType)) {
        $result.Determination   = 'NotAttempted'
        $result.PurgeCapable    = $false
        $result.Blockers        = @($unsupportedBuses[$busType])
        $result.EvidenceSummary = "Purge not available: $($unsupportedBuses[$busType])"
        return [PSCustomObject] $result
    }

    # -----------------------------------------------------------------------
    # Query the device.
    # -----------------------------------------------------------------------
    $protocol = switch ($busType) {
        'NVMe'   { 'NVMe' }
        'SATA'   { 'ATA' }
        'ATA'    { 'ATA' }
        'RAID'   { 'ATA' }
        'SAS'    { 'ATA' }
        'SCSI'   { 'ATA' }
        default  { $null }
    }

    if (-not $protocol) {
        $result.Determination   = 'NotAttempted'
        $result.PurgeCapable    = $null
        $result.Blockers        = @("Bus type '$busType' is not recognised, so no sanitize protocol could be selected. Purge capability is UNKNOWN, not absent.")
        $result.EvidenceSummary = "Purge capability could not be determined: unrecognised bus type '$busType'."
        return [PSCustomObject] $result
    }

    $result.Protocol = $protocol
    $query = Get-StorageIdentifyData -DiskNumber $DiskNumber -Protocol $protocol

    if (-not $query.Success) {
        # A failed query is UNKNOWN. Reporting $false here would let a driver that
        # merely refuses the IOCTL masquerade as a drive that cannot be purged.
        $result.Determination = 'QueryFailed'
        $result.PurgeCapable  = $null
        $result.QueryError    = $query.Error
        $hint = if ($busType -eq 'RAID') {
            ' The controller is in RAID mode, which commonly rejects pass-through; switching it to AHCI usually resolves this.'
        } else { '' }
        $result.Blockers        = @("The device did not answer the capability query: $($query.Error).$hint Purge capability is UNKNOWN, not absent.")
        $result.EvidenceSummary = "Purge capability could not be determined: the device did not answer the capability query."
        return [PSCustomObject] $result
    }

    # -----------------------------------------------------------------------
    # Interpret.
    # -----------------------------------------------------------------------
    if ($protocol -eq 'NVMe') {
        $parsed = ConvertFrom-NvmeIdentifyController -Bytes $query.Data
    }
    else {
        # The media type is REQUIRED to interpret the answer, because SP 800-88
        # Rev.1 credits different commands as Purge on rotational and on flash
        # media. Normalised the same way Get-DiskMediaType does it; anything we
        # cannot positively identify stays 'Unknown' and is handled below rather
        # than being assumed either way.
        $normalisedMedia = switch ($mediaType) {
            'SSD'   { 'SSD' }
            'HDD'   { 'HDD' }
            default { 'Unknown' }
        }
        $parsed = ConvertFrom-AtaIdentifyDevice -Bytes $query.Data -MediaType $normalisedMedia
        if ($parsed.Parsed) {
            $result.SecurityFrozen = $parsed.SecurityFrozen
        }
    }

    if (-not $parsed.Parsed) {
        $result.Determination   = 'QueryFailed'
        $result.PurgeCapable    = $null
        $result.QueryError      = $parsed.ParseError
        $result.Blockers        = @("The device answered but the response could not be parsed: $($parsed.ParseError) Purge capability is UNKNOWN, not absent.")
        $result.EvidenceSummary = 'Purge capability could not be determined: the device response could not be parsed.'
        return [PSCustomObject] $result
    }

    $result.Determination  = 'Queried'
    $result.DeviceAnswered = $true
    $result.PurgeMethods   = @($parsed.PurgeMethods)
    $result.PurgeCapable   = ($parsed.PurgeMethods.Count -gt 0)
    $result.Raw            = $parsed.Raw

    # THE THREE-STATE RULE, APPLIED TO THE MEDIA TYPE.
    #
    # A device can report a command that reaches Purge on one medium and not on
    # another: SANITIZE OVERWRITE EXT purges a platter but is not credited on
    # flash, and SECURITY ERASE UNIT is Purge on a platter but Clear only on
    # flash. If we could not identify the medium, then whether this device can be
    # purged is UNKNOWN, and it must not be recorded as $false. $false here would
    # read as "the device answered and reported nothing qualifying", which is a
    # different and stronger claim than the one the evidence supports.
    $mediaPending = @($parsed.MediaDependentUncredited)
    if (-not $result.PurgeCapable -and $mediaPending.Count -gt 0) {
        $result.PurgeCapable = $null
    }

    if ($parsed.ModelNumber)  { $result.FriendlyName = $parsed.ModelNumber }
    if ($parsed.SerialNumber) { $result.SerialNumber = $parsed.SerialNumber }

    $blockers = @()

    # A frozen drive refuses SECURITY ERASE. Most firmware issues SECURITY FREEZE
    # LOCK at boot so that malware cannot password-lock the drive, so this is the
    # normal state rather than an anomaly. Booting WinPE does not clear it; only an
    # S3 suspend/resume or a hot re-plug of the data cable does. Say that, rather
    # than failing obscurely later.
    if ($protocol -eq 'ATA' -and $parsed.SecurityFrozen) {
        $blockers += 'The ATA security feature set is FROZEN, which is the normal state after boot and blocks SECURITY ERASE UNIT. Clear it with an S3 suspend/resume or by hot re-plugging the data cable. ATA SANITIZE is not affected by the freeze lock.'
    }
    if ($protocol -eq 'ATA' -and $parsed.SecurityLocked) {
        $blockers += 'The ATA security feature set is LOCKED. The drive password must be supplied or the drive reverted via its PSID before any erase can proceed.'
    }
    if ($busType -eq 'RAID') {
        $blockers += 'The disk is behind a RAID controller. Pass-through commands are frequently rejected in RAID mode; AHCI mode is required for reliable sanitize support.'
    }

    $result.Blockers = $blockers

    # -----------------------------------------------------------------------
    # One honest line for the certificate.
    # -----------------------------------------------------------------------
    # The wording is chosen so that it can never be mistaken for a claim that
    # Purge was PERFORMED. Phase 1 performs nothing.
    if ($result.PurgeCapable) {
        $summary = "Sanitization achieved: Clear. Purge is available on this device via " +
                   ($result.PurgeMethods -join '; ') + "; NOT PERFORMED by this operation."
        if ($blockers.Count -gt 0) {
            $summary += ' Outstanding blockers: ' + ($blockers -join ' ')
        }
    }
    elseif ($null -eq $result.PurgeCapable) {
        $summary = 'Sanitization achieved: Clear. Purge capability could not be determined: the device reports ' +
                   ($mediaPending -join '; ') +
                   ", but whether that reaches Purge under NIST SP 800-88 Rev.1 depends on the media type, which could not be identified for this disk (reported as '$mediaType'). This is UNKNOWN, not absent."
        $blockers += "The media type could not be identified, and every command this device reports is credited as Purge on one media type but not the other. Identify the medium before relying on a Purge claim."
        $result.Blockers = $blockers
    }
    else {
        $summary = 'Sanitization achieved: Clear. The device reports no command that reaches Purge, so Purge is not available on this device.'
    }
    $result.EvidenceSummary = $summary

    [PSCustomObject] $result
}

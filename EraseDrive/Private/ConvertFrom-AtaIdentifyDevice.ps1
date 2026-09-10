function ConvertFrom-AtaIdentifyDevice {
    <#
    .SYNOPSIS
        Parses an ATA IDENTIFY DEVICE structure into sanitize capabilities.

    .DESCRIPTION
        Pure function: takes the 512-byte IDENTIFY DEVICE response and reports what
        the device says it supports. Performs no I/O, so it can be tested against
        synthetic buffers across the full cross-product of capability bits.

        Field offsets are from the ATA Command Set (ACS) IDENTIFY DEVICE data,
        which is defined in 16-bit WORDS. Word N begins at byte offset N * 2.

          Word 59   bit 12 = SANITIZE feature set supported
                    bit 13 = CRYPTO SCRAMBLE EXT supported
                    bit 14 = OVERWRITE EXT supported
                    bit 15 = BLOCK ERASE EXT supported
          Word 82   bit 1  = Security feature set supported
          Word 85   bit 1  = Security feature set enabled
          Word 128         = Security status
                    bit 0  = Security supported
                    bit 1  = Security enabled
                    bit 2  = Security locked
                    bit 3  = Security FROZEN
                    bit 4  = Security count expired
                    bit 5  = Enhanced security erase supported

        UNVERIFIED, and it must be resolved before Phase 3 issues any command
        based on it: the word 59 bit assignments above are recorded from the ACS
        specification but were NOT checked against the published standard while
        this was written, because no copy of ACS-4 is available on this machine
        and the reference library has no storage material (D:\Books\BOOKLIST.md
        names DFIR as an explicit gap). The word 128 and word 82/85 assignments
        are the long-standing, widely implemented ones and are not in doubt.

        Separately, the NIST half of this deferral is NO LONGER OPEN. Which of
        these commands is credited as Purge was verified against the published
        SP 800-88 Rev.1 on 2026-09-10, and the crediting block below now cites
        it directly. That verification says nothing about the bit positions
        above, which are a different question against a different standard.

        This is safe to ship in Phase 1 because Phase 1 only REPORTS, and the raw
        word is always returned alongside the interpretation so a wrong bit is
        visible rather than silent. It is NOT safe to ship in Phase 3, where the
        same bits would gate issuing a destructive command. Phase 3's definition
        of done must include checking word 59 against ACS-4 and either confirming
        or correcting this block.

    .PARAMETER Bytes
        The IDENTIFY DEVICE response. Must be at least 512 bytes.

    .OUTPUTS
        PSCustomObject describing the supported sanitize operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        # An empty array is a FAILED QUERY, and must reach the length check below
        # to be reported as unknown. Without this it fails parameter binding, and
        # a caller handling that exception would be one short step from treating
        # "no data" as "no capabilities".
        [AllowEmptyCollection()]
        [byte[]] $Bytes,

        # Which commands reach Purge depends on the media type, and NIST SP
        # 800-88 Rev.1 Appendix A gives two different lists. See the crediting
        # block below. 'Unknown' is the safe default: it credits only what both
        # lists agree on and defers the rest to MediaDependentUncredited, rather
        # than guessing a media type in the tool's own favour.
        [Parameter(Position = 1)]
        [ValidateSet('SSD', 'HDD', 'Unknown')]
        [string] $MediaType = 'Unknown'
    )

    if ($null -eq $Bytes -or $Bytes.Length -lt 512) {
        return [PSCustomObject]@{
            Parsed                = $false
            ParseError            = if ($null -eq $Bytes) { 'No data returned.' }
                                    else { "IDENTIFY DEVICE data was $($Bytes.Length) bytes; 512 are required." }
            ModelNumber           = $null
            SerialNumber          = $null
            FirmwareRevision      = $null
            SupportsSanitize      = $null
            SupportsCryptoScramble = $null
            SupportsBlockErase    = $null
            SupportsOverwriteExt  = $null
            SupportsSecurityErase = $null
            SupportsEnhancedErase = $null
            SecurityEnabled       = $null
            SecurityLocked        = $null
            SecurityFrozen        = $null
            MediaType             = $MediaType
            ReportedCommands      = @()
            PurgeMethods          = @()
            MediaDependentUncredited = @()
            Raw                   = $null
        }
    }

    # ATA strings are stored with the two bytes of each word swapped.
    function Get-AtaString {
        param([byte[]] $Buffer, [int] $ByteOffset, [int] $ByteLength)
        $chars = New-Object char[] $ByteLength
        for ($i = 0; $i -lt $ByteLength; $i += 2) {
            $chars[$i]     = [char] $Buffer[$ByteOffset + $i + 1]
            $chars[$i + 1] = [char] $Buffer[$ByteOffset + $i]
        }
        (-join $chars).Trim()
    }

    $serial   = Get-AtaString -Buffer $Bytes -ByteOffset 20 -ByteLength 20   # words 10-19
    $firmware = Get-AtaString -Buffer $Bytes -ByteOffset 46 -ByteLength 8    # words 23-26
    $model    = Get-AtaString -Buffer $Bytes -ByteOffset 54 -ByteLength 40   # words 27-46

    $word59  = [BitConverter]::ToUInt16($Bytes, 59 * 2)
    $word82  = [BitConverter]::ToUInt16($Bytes, 82 * 2)
    $word85  = [BitConverter]::ToUInt16($Bytes, 85 * 2)
    $word128 = [BitConverter]::ToUInt16($Bytes, 128 * 2)

    $sanitizeSupported = [bool]($word59 -band 0x1000)
    $cryptoScramble    = [bool]($word59 -band 0x2000)
    $overwriteExt      = [bool]($word59 -band 0x4000)
    $blockErase        = [bool]($word59 -band 0x8000)

    $securitySupported = [bool]($word82 -band 0x0002)
    $securityEnabled   = [bool]($word85 -band 0x0002)

    $secLocked         = [bool]($word128 -band 0x0004)
    $secFrozen         = [bool]($word128 -band 0x0008)
    $enhancedErase     = [bool]($word128 -band 0x0020)

    # Everything the device advertises, credited or not. Reported separately so
    # that declining to credit a command is never the same thing as hiding it.
    $reported = @()
    if ($sanitizeSupported -and $cryptoScramble) { $reported += 'ATA SANITIZE, CRYPTO SCRAMBLE EXT' }
    if ($sanitizeSupported -and $blockErase)     { $reported += 'ATA SANITIZE, BLOCK ERASE EXT' }
    if ($sanitizeSupported -and $overwriteExt)   { $reported += 'ATA SANITIZE, OVERWRITE EXT' }
    if ($securitySupported -and $enhancedErase)  { $reported += 'ATA SECURITY ERASE UNIT, enhanced' }

    # ------------------------------------------------------------------------
    # WHICH COMMANDS COUNT AS PURGE IS MEDIA-TYPE DEPENDENT.
    # ------------------------------------------------------------------------
    # Verified 2026-09-10 against the published standard, NIST SP 800-88 Rev.1,
    # Appendix A, Table A-5 (magnetic media) and Table A-8 (flash memory):
    #   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
    #
    # "ATA Hard Disk Drives" (printed p.32), under Purge:
    #   1a. "The overwrite EXT command. Apply one write pass of a fixed pattern
    #        across the media surface. ... A single write pass should suffice to
    #        Purge the media."
    #   1b. "... the Cryptographic Erase (also known as CRYPTO SCRAMBLE EXT)
    #        command."
    #   2.  "Use the ATA Security feature set's SECURE ERASE UNIT command, if
    #        support, in Enhanced Erase mode." [sic] "The ATA Sanitize Device
    #        feature set commands are preferred over the ... SECURITY ERASE UNIT
    #        command when supported by the ATA device."
    #
    # "ATA Solid State Drives (SSDs)" (printed p.36), under Purge:
    #   1a. "The block erase command."
    #   1b. "If the device supports encryption, the Cryptographic Erase (also
    #        known as sanitize crypto scramble) command."
    #   and in that section's Notes, decisively:
    #   "Whereas ATA Secure Erase was a Purge mechanism for magnetic media, it is
    #    only a Clear mechanism for flash memory due to variability in
    #    implementation and the possibility that sensitive data may remain in
    #    areas such as spare cells that have been rotated out of use."
    #   In that same section SECURITY ERASE UNIT appears under CLEAR, not Purge,
    #   and SANITIZE OVERWRITE EXT does not appear in the flash Purge list at all.
    #
    # The resulting credit table:
    #
    #   Command                 Rotational        Flash
    #   CRYPTO SCRAMBLE EXT     Purge             Purge
    #   OVERWRITE EXT           Purge             not listed  (do not credit)
    #   BLOCK ERASE EXT         not listed        Purge
    #   SECURITY ERASE UNIT     Purge (enhanced)  CLEAR ONLY  (do not credit)
    #
    # This corrects two errors in the version that credited without knowing the
    # media type. It OVER-claimed, by crediting SECURITY ERASE UNIT on flash,
    # which is the direction that puts an unearned compliance claim on a
    # certificate. It also UNDER-claimed, by refusing OVERWRITE EXT on rotational
    # drives, where the standard credits a single pass in as many words.
    #
    # UNKNOWN MEDIA TYPE credits only the intersection, which is CRYPTO SCRAMBLE
    # EXT alone. Anything media-dependent goes to MediaDependentUncredited so the
    # caller reports UNKNOWN rather than "this device cannot be purged". A media
    # type we failed to read and a device that answered no are different facts,
    # and collapsing them is the same defect as a failed query reported as a
    # refusal.
    $purgeMethods = @()
    $mediaPending = @()

    if ($sanitizeSupported -and $cryptoScramble) {
        # Credited on every media type; no branch needed.
        $purgeMethods += 'ATA SANITIZE, CRYPTO SCRAMBLE EXT'
    }
    if ($sanitizeSupported -and $blockErase) {
        switch ($MediaType) {
            'SSD'   { $purgeMethods += 'ATA SANITIZE, BLOCK ERASE EXT' }
            'HDD'   { }   # absent from the rotational Purge list
            default { $mediaPending += 'ATA SANITIZE, BLOCK ERASE EXT' }
        }
    }
    if ($sanitizeSupported -and $overwriteExt) {
        switch ($MediaType) {
            'HDD'   { $purgeMethods += 'ATA SANITIZE, OVERWRITE EXT' }
            'SSD'   { }   # absent from the flash Purge list
            default { $mediaPending += 'ATA SANITIZE, OVERWRITE EXT' }
        }
    }
    if ($securitySupported -and $enhancedErase) {
        switch ($MediaType) {
            'HDD'   { $purgeMethods += 'ATA SECURITY ERASE UNIT, enhanced' }
            'SSD'   { }   # Clear only on flash, per the Notes quoted above
            default { $mediaPending += 'ATA SECURITY ERASE UNIT, enhanced' }
        }
    }

    [PSCustomObject]@{
        Parsed                 = $true
        ParseError             = $null
        ModelNumber            = $model
        SerialNumber           = $serial
        FirmwareRevision       = $firmware
        SupportsSanitize       = $sanitizeSupported
        SupportsCryptoScramble = $cryptoScramble
        SupportsBlockErase     = $blockErase
        SupportsOverwriteExt   = $overwriteExt
        SupportsSecurityErase  = $securitySupported
        SupportsEnhancedErase  = $enhancedErase
        SecurityEnabled        = $securityEnabled
        SecurityLocked         = $secLocked
        SecurityFrozen         = $secFrozen
        MediaType              = $MediaType
        ReportedCommands       = $reported
        PurgeMethods           = $purgeMethods
        MediaDependentUncredited = $mediaPending
        Raw                    = [ordered]@{
            Word59  = ('0x{0:X4}' -f $word59)
            Word82  = ('0x{0:X4}' -f $word82)
            Word85  = ('0x{0:X4}' -f $word85)
            Word128 = ('0x{0:X4}' -f $word128)
        }
    }
}

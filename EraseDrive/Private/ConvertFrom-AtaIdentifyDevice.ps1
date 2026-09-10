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
        [byte[]] $Bytes
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
            PurgeMethods          = @()
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

    # Only block erase and crypto scramble are credited as Purge. OVERWRITE EXT is
    # reported because the device advertises it, but is not credited, because a
    # controller-driven overwrite does not reach over-provisioned or retired
    # flash blocks, which is the whole reason overwriting cannot Purge an SSD.
    #
    # This is STRICTER than NIST SP 800-88 Rev.1 appears to be: Appendix A lists
    # SANITIZE OVERWRITE EXT among the ATA Purge techniques. Under-claiming is the
    # safe direction for a compliance certificate, and on a rotational ATA drive
    # the objection above does not apply, so this may be worth relaxing for HDDs
    # specifically. Check against Appendix A before Phase 3 ships and correct this
    # comment either way; no copy of the standard was available on the machine
    # where this was written.
    $purgeMethods = @()
    if ($sanitizeSupported -and $cryptoScramble) { $purgeMethods += 'ATA SANITIZE, CRYPTO SCRAMBLE EXT' }
    if ($sanitizeSupported -and $blockErase)     { $purgeMethods += 'ATA SANITIZE, BLOCK ERASE EXT' }
    if ($securitySupported -and $enhancedErase)  { $purgeMethods += 'ATA SECURITY ERASE UNIT, enhanced' }

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
        PurgeMethods           = $purgeMethods
        Raw                    = [ordered]@{
            Word59  = ('0x{0:X4}' -f $word59)
            Word82  = ('0x{0:X4}' -f $word82)
            Word85  = ('0x{0:X4}' -f $word85)
            Word128 = ('0x{0:X4}' -f $word128)
        }
    }
}

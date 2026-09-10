function ConvertFrom-NvmeIdentifyController {
    <#
    .SYNOPSIS
        Parses an NVMe Identify Controller structure into sanitize capabilities.

    .DESCRIPTION
        Pure function: takes the 4096-byte Identify Controller data structure and
        reports what the controller says it can do. It performs no I/O, which is
        deliberate. The bit parsing is where a capability report is most likely to
        be quietly wrong, so it is separated from the device access in order that
        it can be tested against synthetic buffers across the full cross-product of
        capability bits rather than against whichever drive happens to be in the
        machine.

        Field offsets are from the NVM Express Base Specification, Figure
        "Identify Controller Data Structure":

          Bytes 256:257  OACS    Optional Admin Command Support
                                 bit 1 = Format NVM command supported
          Bytes 328:331  SANICAP Sanitize Capabilities
                                 bit 0 = Crypto Erase Sanitize supported
                                 bit 1 = Block Erase Sanitize supported
                                 bit 2 = Overwrite Sanitize supported
          Byte  524      FNA     Format NVM Attributes
                                 bit 0 = format applies to all namespaces
                                 bit 1 = secure erase applies to all namespaces
                                 bit 2 = cryptographic erase supported (SES=2)

        A drive can support Format NVM without supporting the Sanitize command,
        and the reverse. Both are reported, because they are different commands
        with different guarantees, and collapsing them into one boolean is how the
        function this replaces came to claim a capability it never checked.

    .PARAMETER Bytes
        The Identify Controller data structure. Must be at least 528 bytes so that
        FNA at offset 524 is readable; a conformant structure is 4096.

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

    # A short buffer is a failed query, not a drive without capabilities. Saying
    # "not supported" here would be exactly the lie this whole change exists to
    # remove, so it is reported as unknown instead.
    if ($null -eq $Bytes -or $Bytes.Length -lt 528) {
        return [PSCustomObject]@{
            Parsed              = $false
            ParseError          = if ($null -eq $Bytes) { 'No data returned.' }
                                  else { "Identify Controller data was $($Bytes.Length) bytes; at least 528 are required." }
            ModelNumber         = $null
            SerialNumber        = $null
            FirmwareRevision    = $null
            SupportsFormatNvm   = $null
            SupportsCryptoErase = $null
            SupportsBlockErase  = $null
            SupportsOverwrite   = $null
            SupportsSanitize    = $null
            PurgeMethods        = @()
            Raw                 = $null
        }
    }

    # Identify strings are ASCII, space padded, NOT null terminated.
    $serial   = ([System.Text.Encoding]::ASCII.GetString($Bytes, 4, 20)).Trim()
    $model    = ([System.Text.Encoding]::ASCII.GetString($Bytes, 24, 40)).Trim()
    $firmware = ([System.Text.Encoding]::ASCII.GetString($Bytes, 64, 8)).Trim()

    $oacs    = [BitConverter]::ToUInt16($Bytes, 256)
    $sanicap = [BitConverter]::ToUInt32($Bytes, 328)
    $fna     = $Bytes[524]

    $supportsFormatNvm = [bool]($oacs -band 0x0002)

    # Format NVM with SES=2 is a cryptographic erase. It is a different command
    # from Sanitize crypto erase and is reported separately.
    $formatCryptoErase = [bool]($fna -band 0x04)

    $sanitizeCrypto    = [bool]($sanicap -band 0x1)
    $sanitizeBlock     = [bool]($sanicap -band 0x2)
    $sanitizeOverwrite = [bool]($sanicap -band 0x4)

    # Which of these count as Purge is a DELIBERATELY CONSERVATIVE choice, and it
    # is not a verbatim reading of the standard.
    #
    # NIST SP 800-88 Rev.1 is dated 2014 and predates the NVMe Sanitize command
    # (NVMe 1.3, 2017), so Appendix A cannot name it. Crediting Sanitize block and
    # crypto erase as Purge is therefore an inference from the way the same
    # document treats the equivalent ATA SANITIZE operations. Format NVM is
    # different: Appendix A does address NVM Express directly.
    #
    # Sanitize Overwrite is reported but NOT credited as Purge, because a
    # controller-driven overwrite still reaches only mapped blocks and leaves
    # over-provisioned, retired and un-erased flash untouched. NOTE that this is
    # STRICTER than the standard appears to be for ATA, where SANITIZE OVERWRITE
    # EXT is listed among the Purge techniques. Erring toward under-claiming is
    # the right direction for a compliance certificate, but the exact position
    # should be checked against SP 800-88 Rev.1 Appendix A before Phase 2 ships,
    # and this comment corrected either way. No copy of the standard was
    # available on the machine where this was written.
    $purgeMethods = @()
    if ($sanitizeCrypto)    { $purgeMethods += 'NVMe Sanitize, crypto erase' }
    if ($sanitizeBlock)     { $purgeMethods += 'NVMe Sanitize, block erase' }
    if ($supportsFormatNvm -and $formatCryptoErase) { $purgeMethods += 'NVMe Format NVM, SES=2 cryptographic erase' }
    if ($supportsFormatNvm -and -not $formatCryptoErase) { $purgeMethods += 'NVMe Format NVM, SES=1 user data erase' }

    [PSCustomObject]@{
        Parsed              = $true
        ParseError          = $null
        ModelNumber         = $model
        SerialNumber        = $serial
        FirmwareRevision    = $firmware
        SupportsFormatNvm   = $supportsFormatNvm
        SupportsCryptoErase = ($sanitizeCrypto -or ($supportsFormatNvm -and $formatCryptoErase))
        SupportsBlockErase  = $sanitizeBlock
        SupportsOverwrite   = $sanitizeOverwrite
        SupportsSanitize    = ($sanitizeCrypto -or $sanitizeBlock -or $sanitizeOverwrite)
        PurgeMethods        = $purgeMethods
        Raw                 = [ordered]@{
            OACS    = ('0x{0:X4}' -f $oacs)
            SANICAP = ('0x{0:X8}' -f $sanicap)
            FNA     = ('0x{0:X2}' -f $fna)
        }
    }
}

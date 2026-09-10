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

    # Which of these count as Purge. CHECKED against the published standard on
    # 2026-09-10, NIST SP 800-88 Rev.1 Appendix A, Table A-8, section "NVM Express
    # SSDs" (printed p.38):
    #   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
    #
    # The standard DOES address NVM Express directly, and its Purge list is:
    #   1. "Apply the NVM Express Format command, if supported. One or both of the
    #       following options may be available: a. The User Data Erase command.
    #       b. If the device supports encryption, the Cryptographic Erase command."
    #   2. "Cryptographic Erase through the TCG Opal SSC or Enterprise SSC
    #       interface by issuing commands as necessary to cause all MEKs to be
    #       changed."
    # So crediting Format NVM with SES=1 or SES=2 is a VERBATIM reading, not an
    # inference. This is also why Phase 2 targets Format NVM: it is the command
    # the standard actually names for this media type.
    #
    # CREDITING NVMe SANITIZE IS STILL AN INFERENCE, and is labelled as one.
    # SP 800-88 Rev.1 is dated 2014 and the NVMe Sanitize command arrived in NVMe
    # 1.3 in 2017, so the document cannot and does not name it. Sanitize block
    # erase and crypto erase are credited here by analogy with the ATA SANITIZE
    # operations that the same document credits on flash media. The analogy is
    # strong, since NVMe Sanitize is the stronger operation and applies to the
    # whole NVM subsystem rather than a namespace, but it is an argument and not a
    # citation. A certificate that rests on it must say so.
    #
    # Sanitize Overwrite is reported but NOT credited. This is now known to AGREE
    # with the standard rather than being stricter than it: the earlier comment
    # here claimed Appendix A lists SANITIZE OVERWRITE EXT among the ATA Purge
    # techniques, which is true ONLY for rotational ATA drives (printed p.32).
    # For flash, the ATA SSD Purge list (printed p.36) offers block erase and
    # crypto scramble and does NOT include overwrite, for exactly the reason that
    # applies here: a controller-driven overwrite reaches only mapped blocks and
    # leaves over-provisioned, retired and un-erased flash untouched. NVMe is
    # flash, so the flash list is the applicable one.
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

<#
    Tests for NIST SP 800-88 Purge capability DETECTION (Phase 1).

    The thing under test is a capability report that feeds an audit log and a
    compliance certificate, replacing a value that used to be inferred from the
    bus type without ever asking the device. So these tests are written against
    the invariant rather than against an illustrative example:

      * the bit parsers are exercised over the FULL CROSS-PRODUCT of the
        capability bits, not over one drive that happens to be in a machine;

      * every path that does not get an answer from the device is asserted to
        report $null, never $false. That distinction is the whole point of the
        change, and it is exactly the kind of thing a single happy-path test
        would let regress silently.

    One buffer here is real: the NVMe values captured from the KIOXIA
    KBG60ZNV512G in DES-70072 on 2026-09-10 (OACS=0x0017, SANICAP=0x60000002,
    FNA=0x00). It is pinned so that a refactor which breaks parsing of a device
    known to exist fails loudly.
#>

BeforeAll {
    $modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'EraseDrive'

    $Script:EraseDriveConfig = @{
        LogDirectory  = $env:TEMP
        LogFile       = Join-Path $env:TEMP 'EraseDrive-saniTest.log'
        MaxLogSizeMB  = 1
        MaxLogFiles   = 1
    }

    Get-ChildItem (Join-Path $modulePath 'Private') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

    # Builds a synthetic NVMe Identify Controller structure.
    function New-NvmeIdentify {
        param(
            [uint16] $Oacs    = 0,
            [uint32] $Sanicap = 0,
            [byte]   $Fna     = 0,
            [string] $Model   = 'TEST MODEL',
            [string] $Serial  = 'TESTSERIAL',
            [string] $Firmware = 'FW1',
            [int]    $Length  = 4096
        )
        $b = New-Object byte[] $Length
        # Strings are ASCII, space padded, not null terminated.
        $pad = { param($s, $len) ($s.PadRight($len)).Substring(0, $len) }
        [System.Text.Encoding]::ASCII.GetBytes((& $pad $Serial 20)).CopyTo($b, 4)
        [System.Text.Encoding]::ASCII.GetBytes((& $pad $Model 40)).CopyTo($b, 24)
        [System.Text.Encoding]::ASCII.GetBytes((& $pad $Firmware 8)).CopyTo($b, 64)
        [BitConverter]::GetBytes($Oacs).CopyTo($b, 256)
        [BitConverter]::GetBytes($Sanicap).CopyTo($b, 328)
        $b[524] = $Fna
        return ,$b
    }

    # Builds a synthetic ATA IDENTIFY DEVICE structure (512 bytes, 256 words).
    function New-AtaIdentify {
        param(
            [uint16] $Word59  = 0,
            [uint16] $Word82  = 0,
            [uint16] $Word85  = 0,
            [uint16] $Word128 = 0,
            [string] $Model   = 'ATA TEST MODEL',
            [string] $Serial  = 'ATASERIAL',
            [int]    $Length  = 512
        )
        $b = New-Object byte[] $Length
        # ATA stores strings with the bytes of each word swapped.
        $writeSwapped = {
            param($buffer, $offset, $text, $len)
            $t = ($text.PadRight($len)).Substring(0, $len)
            $raw = [System.Text.Encoding]::ASCII.GetBytes($t)
            for ($i = 0; $i -lt $len; $i += 2) {
                $buffer[$offset + $i]     = $raw[$i + 1]
                $buffer[$offset + $i + 1] = $raw[$i]
            }
        }
        & $writeSwapped $b 20 $Serial 20
        & $writeSwapped $b 54 $Model 40
        [BitConverter]::GetBytes($Word59).CopyTo($b, 118)
        [BitConverter]::GetBytes($Word82).CopyTo($b, 164)
        [BitConverter]::GetBytes($Word85).CopyTo($b, 170)
        [BitConverter]::GetBytes($Word128).CopyTo($b, 256)
        return ,$b
    }
}

Describe 'ConvertFrom-NvmeIdentifyController' {

    It 'Parses the real KIOXIA KBG60ZNV512G values captured on 2026-09-10' {
        # OACS=0x0017 (Format NVM supported), SANICAP=0x60000002 (block erase
        # only), FNA=0x00 (no crypto erase via Format).
        $buf = New-NvmeIdentify -Oacs 0x0017 -Sanicap 0x60000002 -Fna 0x00 `
                                -Model 'KBG60ZNV512G KIOXIA' -Serial 'ZEKCT5YCZ0JS'
        $r = ConvertFrom-NvmeIdentifyController $buf

        $r.Parsed              | Should -BeTrue
        $r.ModelNumber         | Should -Be 'KBG60ZNV512G KIOXIA'
        $r.SerialNumber        | Should -Be 'ZEKCT5YCZ0JS'
        $r.SupportsFormatNvm   | Should -BeTrue
        $r.SupportsBlockErase  | Should -BeTrue
        $r.SupportsCryptoErase | Should -BeFalse
        $r.SupportsOverwrite   | Should -BeFalse
        $r.PurgeMethods        | Should -Contain 'NVMe Sanitize, block erase'
    }

    It 'Reports every Supports flag as $null, never $false, when the buffer is short' {
        # A failed query must not be able to masquerade as a drive with no
        # capabilities. This is the invariant the whole design turns on.
        foreach ($len in @(0, 1, 100, 527)) {
            $r = ConvertFrom-NvmeIdentifyController (New-Object byte[] $len)
            $r.Parsed              | Should -BeFalse -Because "length $len is too short"
            $r.SupportsFormatNvm   | Should -BeNullOrEmpty
            $r.SupportsCryptoErase | Should -BeNullOrEmpty
            $r.SupportsBlockErase  | Should -BeNullOrEmpty
            $r.SupportsSanitize    | Should -BeNullOrEmpty
            $null -eq $r.SupportsBlockErase | Should -BeTrue -Because 'it must be $null, not $false'
        }
    }

    It 'Reports $null rather than $false for a null buffer' {
        $r = ConvertFrom-NvmeIdentifyController $null
        $r.Parsed | Should -BeFalse
        $null -eq $r.SupportsSanitize | Should -BeTrue
    }

    It 'Maps the SANICAP bits correctly across the full cross-product' {
        # 8 combinations of crypto/block/overwrite, each asserted independently
        # rather than trusting one representative value.
        for ($bits = 0; $bits -le 7; $bits++) {
            $expectCrypto    = [bool]($bits -band 1)
            $expectBlock     = [bool]($bits -band 2)
            $expectOverwrite = [bool]($bits -band 4)

            $r = ConvertFrom-NvmeIdentifyController (New-NvmeIdentify -Sanicap ([uint32]$bits))

            $r.SupportsBlockErase | Should -Be $expectBlock     -Because "SANICAP=$bits"
            $r.SupportsOverwrite  | Should -Be $expectOverwrite -Because "SANICAP=$bits"
            $r.SupportsSanitize   | Should -Be ($expectCrypto -or $expectBlock -or $expectOverwrite) -Because "SANICAP=$bits"
        }
    }

    It 'Treats Format NVM SES=2 as a crypto erase only when OACS also allows Format' {
        # FNA bit 2 alone means nothing if the Format NVM command is unsupported.
        $noFormat = ConvertFrom-NvmeIdentifyController (New-NvmeIdentify -Oacs 0x0000 -Fna 0x04)
        $noFormat.SupportsFormatNvm   | Should -BeFalse
        $noFormat.SupportsCryptoErase | Should -BeFalse
        $noFormat.PurgeMethods        | Should -BeNullOrEmpty

        $withFormat = ConvertFrom-NvmeIdentifyController (New-NvmeIdentify -Oacs 0x0002 -Fna 0x04)
        $withFormat.SupportsFormatNvm   | Should -BeTrue
        $withFormat.SupportsCryptoErase | Should -BeTrue
        $withFormat.PurgeMethods        | Should -Contain 'NVMe Format NVM, SES=2 cryptographic erase'
    }

    It 'Does NOT credit Sanitize Overwrite as a Purge method' {
        # Overwrite driven by the controller still cannot reach over-provisioned
        # or retired flash, so it must not appear as a route to Purge.
        $r = ConvertFrom-NvmeIdentifyController (New-NvmeIdentify -Sanicap 0x4)
        $r.SupportsOverwrite | Should -BeTrue
        $r.PurgeMethods      | Should -BeNullOrEmpty
    }

    It 'Reports no Purge methods for a device with no capabilities at all' {
        $r = ConvertFrom-NvmeIdentifyController (New-NvmeIdentify)
        $r.Parsed       | Should -BeTrue
        $r.PurgeMethods | Should -BeNullOrEmpty
    }
}

Describe 'ConvertFrom-AtaIdentifyDevice' {

    It 'Byte-swaps ATA strings correctly' {
        $r = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Model 'SAMSUNG SSD 860' -Serial 'S3Z9NB0K')
        $r.ModelNumber  | Should -Be 'SAMSUNG SSD 860'
        $r.SerialNumber | Should -Be 'S3Z9NB0K'
    }

    It 'Reports every Supports flag as $null, never $false, when the buffer is short' {
        foreach ($len in @(0, 1, 511)) {
            $r = ConvertFrom-AtaIdentifyDevice (New-Object byte[] $len)
            $r.Parsed | Should -BeFalse -Because "length $len is too short"
            $null -eq $r.SupportsSanitize  | Should -BeTrue -Because 'it must be $null, not $false'
            $null -eq $r.SecurityFrozen    | Should -BeTrue -Because 'unknown, not "not frozen"'
        }
    }

    It 'Maps word 59 sanitize bits across the full cross-product' {
        # bit 12 SANITIZE supported, 13 CRYPTO SCRAMBLE, 14 OVERWRITE, 15 BLOCK ERASE
        for ($combo = 0; $combo -le 15; $combo++) {
            $word = [uint16](($combo -shl 12) -band 0xFFFF)
            $r = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 $word)

            $r.SupportsSanitize       | Should -Be ([bool]($combo -band 1)) -Because "word59=0x$('{0:X4}' -f $word)"
            $r.SupportsCryptoScramble | Should -Be ([bool]($combo -band 2)) -Because "word59=0x$('{0:X4}' -f $word)"
            $r.SupportsOverwriteExt   | Should -Be ([bool]($combo -band 4)) -Because "word59=0x$('{0:X4}' -f $word)"
            $r.SupportsBlockErase     | Should -Be ([bool]($combo -band 8)) -Because "word59=0x$('{0:X4}' -f $word)"
        }
    }

    It 'Only credits SANITIZE methods when the SANITIZE feature set itself is supported' {
        # Advertising CRYPTO SCRAMBLE EXT without the feature set bit must not
        # produce a Purge claim.
        $r = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 0x2000)
        $r.SupportsCryptoScramble | Should -BeTrue
        $r.SupportsSanitize       | Should -BeFalse
        $r.PurgeMethods           | Should -BeNullOrEmpty

        $r2 = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 0x3000)
        $r2.PurgeMethods | Should -Contain 'ATA SANITIZE, CRYPTO SCRAMBLE EXT'
    }

    It 'Reads word 59 bits 10 and 11 without crediting either toward Purge' {
        # Verified against ACS-3 Table 45 (p.106): bit 10 SANITIZE ANTIFREEZE
        # LOCK EXT supported, bit 11 commands-during-sanitize follow ACS-3 rules.
        # They are operator-relevant for Phase 3 and must never reach PurgeMethods.
        $neither = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 0x0000)
        $neither.SupportsSanitizeAntifreezeLock | Should -BeFalse
        $neither.SanitizeCommandsPerAcs3        | Should -BeFalse

        $antifreeze = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 0x0400)
        $antifreeze.SupportsSanitizeAntifreezeLock | Should -BeTrue
        $antifreeze.SanitizeCommandsPerAcs3        | Should -BeFalse
        $antifreeze.PurgeMethods                   | Should -BeNullOrEmpty -Because 'bit 10 is not a Purge command'

        $acs3 = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 0x0800)
        $acs3.SupportsSanitizeAntifreezeLock | Should -BeFalse
        $acs3.SanitizeCommandsPerAcs3        | Should -BeTrue
        $acs3.PurgeMethods                   | Should -BeNullOrEmpty -Because 'bit 11 is not a Purge command'

        $both = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 0x0C00)
        $both.SupportsSanitizeAntifreezeLock | Should -BeTrue
        $both.SanitizeCommandsPerAcs3        | Should -BeTrue
    }

    It 'Reports the new bits as $null, not $false, when the buffer is short' {
        $r = ConvertFrom-AtaIdentifyDevice (New-Object byte[] 16)
        $null -eq $r.SupportsSanitizeAntifreezeLock | Should -BeTrue
        $null -eq $r.SanitizeCommandsPerAcs3        | Should -BeTrue
    }

    It 'Detects the security frozen bit, which is the normal post-boot state' {
        $frozen    = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word128 0x0008)
        $notFrozen = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word128 0x0000)
        $frozen.SecurityFrozen    | Should -BeTrue
        $notFrozen.SecurityFrozen | Should -BeFalse
    }

    It 'Detects locked and enhanced-erase status independently' {
        $r = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word82 0x0002 -Word128 0x0020)
        $r.SecurityLocked        | Should -BeFalse
        $r.SupportsEnhancedErase | Should -BeTrue
        # It is always REPORTED. Whether it is CREDITED as Purge depends on the
        # media type, which is the subject of the next Describe block. This
        # assertion used to read PurgeMethods, and that was the over-claim.
        $r.ReportedCommands      | Should -Contain 'ATA SECURITY ERASE UNIT, enhanced'
    }
}

Describe 'Purge crediting follows the media type, per NIST SP 800-88 Rev.1 Appendix A' {

    # Verified against the published standard on 2026-09-10:
    #   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf
    #
    #   Command                 Rotational (p.32)   Flash (p.36)
    #   CRYPTO SCRAMBLE EXT     Purge               Purge
    #   OVERWRITE EXT           Purge               not listed
    #   BLOCK ERASE EXT         not listed          Purge
    #   SECURITY ERASE UNIT     Purge (enhanced)    Clear only
    #
    # "Whereas ATA Secure Erase was a Purge mechanism for magnetic media, it is
    #  only a Clear mechanism for flash memory due to variability in
    #  implementation and the possibility that sensitive data may remain in areas
    #  such as spare cells that have been rotated out of use." (printed p.36)

    It 'Does NOT credit SECURITY ERASE UNIT as Purge on flash' {
        # This is the regression guard for a real over-claim: the shipped version
        # credited this on every media type, which would have put an unearned
        # Purge claim on the certificate of any SSD reporting enhanced erase.
        $ssd = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word82 0x0002 -Word128 0x0020) -MediaType 'SSD'
        $ssd.PurgeMethods     | Should -BeNullOrEmpty
        $ssd.ReportedCommands | Should -Contain 'ATA SECURITY ERASE UNIT, enhanced' -Because 'declining to credit must never mean hiding'
    }

    It 'Credits SECURITY ERASE UNIT as Purge on rotational media' {
        $hdd = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word82 0x0002 -Word128 0x0020) -MediaType 'HDD'
        $hdd.PurgeMethods | Should -Contain 'ATA SECURITY ERASE UNIT, enhanced'
    }

    It 'Credits OVERWRITE EXT on rotational media and not on flash' {
        $w = [uint16]0x5000   # bit 12 SANITIZE feature set + bit 14 OVERWRITE EXT
        (ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 $w) -MediaType 'HDD').PurgeMethods |
            Should -Contain 'ATA SANITIZE, OVERWRITE EXT'
        (ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 $w) -MediaType 'SSD').PurgeMethods |
            Should -BeNullOrEmpty
    }

    It 'Credits BLOCK ERASE EXT on flash and not on rotational media' {
        $w = [uint16]0x9000   # bit 12 SANITIZE feature set + bit 15 BLOCK ERASE EXT
        (ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 $w) -MediaType 'SSD').PurgeMethods |
            Should -Contain 'ATA SANITIZE, BLOCK ERASE EXT'
        (ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 $w) -MediaType 'HDD').PurgeMethods |
            Should -BeNullOrEmpty
    }

    It 'Credits CRYPTO SCRAMBLE EXT on every media type, including unknown' {
        foreach ($m in 'SSD', 'HDD', 'Unknown') {
            (ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 0x3000) -MediaType $m).PurgeMethods |
                Should -Contain 'ATA SANITIZE, CRYPTO SCRAMBLE EXT' -Because "it is on both lists, so it is credited on $m"
        }
    }

    It 'Defers rather than denies when the media type is unknown' {
        # The three-state rule applied to the media type. A command that purges a
        # platter but not flash cannot be judged without knowing which this is,
        # and "cannot be judged" must not be recorded as "cannot be purged".
        $r = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 0x5000 -Word82 0x0002 -Word128 0x0020)
        $r.MediaType                | Should -Be 'Unknown'
        $r.PurgeMethods             | Should -BeNullOrEmpty
        $r.MediaDependentUncredited | Should -Contain 'ATA SANITIZE, OVERWRITE EXT'
        $r.MediaDependentUncredited | Should -Contain 'ATA SECURITY ERASE UNIT, enhanced'
    }

    It 'Never credits a command it did not also report, over the full cross-product' {
        # The invariant, asserted over every media type crossed with every word 59
        # combination and both enhanced-erase states, rather than over one
        # illustrative drive.
        foreach ($media in 'SSD', 'HDD', 'Unknown') {
            for ($combo = 0; $combo -le 15; $combo++) {
                $word = [uint16](($combo -shl 12) -band 0xFFFF)
                foreach ($sec in @([uint16]0x0000, [uint16]0x0020)) {
                    $r = ConvertFrom-AtaIdentifyDevice (New-AtaIdentify -Word59 $word -Word82 0x0002 -Word128 $sec) -MediaType $media
                    $why = "media=$media word59=0x$('{0:X4}' -f $word) word128=0x$('{0:X4}' -f $sec)"

                    foreach ($m in $r.PurgeMethods) {
                        $r.ReportedCommands | Should -Contain $m -Because "credited but not reported: $why"
                    }
                    if ($media -eq 'SSD') {
                        $r.PurgeMethods | Should -Not -Contain 'ATA SECURITY ERASE UNIT, enhanced' -Because "Clear only on flash: $why"
                        $r.PurgeMethods | Should -Not -Contain 'ATA SANITIZE, OVERWRITE EXT'       -Because "not in the flash Purge list: $why"
                    }
                    if ($media -eq 'HDD') {
                        $r.MediaDependentUncredited | Should -BeNullOrEmpty -Because "nothing is deferred once the medium is known: $why"
                    }
                }
            }
        }
    }
}

Describe 'Get-DiskSanitizeCapability' {

    BeforeEach {
        Mock Write-OperationLog {}
    }

    It 'Refuses a USB-attached disk WITHOUT querying it, and says why' {
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '2'; BusType = 'USB'; MediaType = 'SSD'; FriendlyName = 'Some Stick'; SerialNumber = 'X' } }
        Mock Get-StorageIdentifyData { throw 'must not be called for USB' }

        $r = Get-DiskSanitizeCapability -DiskNumber 2

        $r.PurgeCapable   | Should -BeFalse
        $r.DeviceAnswered | Should -BeFalse
        $r.Determination  | Should -Be 'NotAttempted'
        $r.Blockers[0]    | Should -BeLike '*USB*'
        Should -Invoke Get-StorageIdentifyData -Times 0 -Scope It
    }

    It 'Reports PurgeCapable as $null, NOT $false, when the device does not answer' {
        # The single most important invariant here: a driver that refuses the
        # IOCTL must never be recorded as a drive that cannot be purged.
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '0'; BusType = 'NVMe'; MediaType = 'SSD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-StorageIdentifyData { [PSCustomObject]@{ Success = $false; Data = $null; Error = 'Win32 error 1' } }

        $r = Get-DiskSanitizeCapability -DiskNumber 0

        $null -eq $r.PurgeCapable | Should -BeTrue -Because 'unknown must not collapse to false'
        $r.Determination  | Should -Be 'QueryFailed'
        $r.DeviceAnswered | Should -BeFalse
        $r.QueryError     | Should -Be 'Win32 error 1'
    }

    It 'Reports PurgeCapable as $null when the response cannot be parsed' {
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '0'; BusType = 'NVMe'; MediaType = 'SSD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-StorageIdentifyData { [PSCustomObject]@{ Success = $true; Data = (New-Object byte[] 8); Error = $null } }

        $r = Get-DiskSanitizeCapability -DiskNumber 0

        $null -eq $r.PurgeCapable | Should -BeTrue
        $r.Determination | Should -Be 'QueryFailed'
    }

    It 'Reports PurgeCapable as $null for an unrecognised bus type' {
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '9'; BusType = 'Fibre Channel'; MediaType = 'SSD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-StorageIdentifyData { throw 'must not be called' }

        $r = Get-DiskSanitizeCapability -DiskNumber 9

        $null -eq $r.PurgeCapable | Should -BeTrue
        $r.Blockers[0] | Should -BeLike '*UNKNOWN, not absent*'
    }

    It 'Reports a capable device and never implies Purge was performed' {
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '0'; BusType = 'NVMe'; MediaType = 'SSD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-StorageIdentifyData {
            [PSCustomObject]@{ Success = $true; Error = $null
                               Data = (New-NvmeIdentify -Oacs 0x0002 -Sanicap 0x1 -Fna 0x04) }
        }

        $r = Get-DiskSanitizeCapability -DiskNumber 0

        $r.PurgeCapable    | Should -BeTrue
        $r.DeviceAnswered  | Should -BeTrue
        $r.Determination   | Should -Be 'Queried'
        # The certificate line must state availability, never achievement.
        $r.EvidenceSummary | Should -BeLike '*NOT PERFORMED*'
        $r.EvidenceSummary | Should -BeLike '*Sanitization achieved: Clear*'
    }

    It 'Reports PurgeCapable as $null when the credit depends on a media type it could not identify' {
        # Get-PhysicalDisk reports 'Unspecified' more often than is comfortable,
        # and the answer for a drive whose only qualifying command is
        # media-dependent is UNKNOWN, not "cannot be purged".
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '1'; BusType = 'SATA'; MediaType = 'Unspecified'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-StorageIdentifyData {
            [PSCustomObject]@{ Success = $true; Error = $null
                               Data = (New-AtaIdentify -Word59 0x5000) }
        }

        $r = Get-DiskSanitizeCapability -DiskNumber 1

        $null -eq $r.PurgeCapable | Should -BeTrue -Because 'an unidentified medium is not a refusal'
        $r.DeviceAnswered  | Should -BeTrue
        $r.EvidenceSummary | Should -BeLike '*UNKNOWN, not absent*'
        ($r.Blockers -join ' ') | Should -BeLike '*media type could not be identified*'
    }

    It 'Still reports a definite answer once the medium IS identified' {
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '1'; BusType = 'SATA'; MediaType = 'HDD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-StorageIdentifyData {
            [PSCustomObject]@{ Success = $true; Error = $null
                               Data = (New-AtaIdentify -Word59 0x5000) }
        }

        $r = Get-DiskSanitizeCapability -DiskNumber 1

        $r.PurgeCapable  | Should -BeTrue
        $r.PurgeMethods  | Should -Contain 'ATA SANITIZE, OVERWRITE EXT'
    }

    It 'Surfaces the ATA freeze lock as a blocker with the remedy' {
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '1'; BusType = 'SATA'; MediaType = 'SSD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-StorageIdentifyData {
            [PSCustomObject]@{ Success = $true; Error = $null
                               Data = (New-AtaIdentify -Word59 0x3000 -Word128 0x0008) }
        }

        $r = Get-DiskSanitizeCapability -DiskNumber 1

        $r.PurgeCapable    | Should -BeTrue
        $r.SecurityFrozen  | Should -BeTrue
        ($r.Blockers -join ' ') | Should -BeLike '*FROZEN*'
        ($r.Blockers -join ' ') | Should -BeLike '*suspend/resume*'
    }

    It 'Warns that a RAID controller commonly rejects pass-through' {
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '1'; BusType = 'RAID'; MediaType = 'SSD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-StorageIdentifyData { [PSCustomObject]@{ Success = $false; Data = $null; Error = 'rejected' } }

        $r = Get-DiskSanitizeCapability -DiskNumber 1
        ($r.Blockers -join ' ') | Should -BeLike '*AHCI*'
    }
}

Describe 'Get-DiskMediaType reports a measured capability, not an inferred one' {

    BeforeEach {
        Mock Write-OperationLog {}
    }

    It 'Mirrors PurgeCapable including the $null unknown state' {
        # The old behaviour set SupportsSecureErase = $true for any SSD on NVMe or
        # SATA without asking the device. If that inference ever returns, this
        # fails: the mocked device is an NVMe SSD whose query FAILS, which the old
        # code would have called $true.
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '0'; BusType = 'NVMe'; MediaType = 'SSD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-Disk { $null }
        Mock Get-StorageIdentifyData { [PSCustomObject]@{ Success = $false; Data = $null; Error = 'no answer' } }

        $r = Get-DiskMediaType -DiskNumber 0

        $null -eq $r.SupportsSecureErase | Should -BeTrue -Because 'an unanswered query is unknown, not supported'
        $r.SanitizeCapability.Determination | Should -Be 'QueryFailed'
    }

    It 'Reports $false for an SSD whose device answers with no Purge command' {
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage','HealthStatus','VirtualDisk' { [PSCustomObject]@{ DeviceId = '0'; BusType = 'NVMe'; MediaType = 'SSD'; FriendlyName = 'D'; SerialNumber = 'S' } }
        Mock Get-Disk { $null }
        Mock Get-StorageIdentifyData {
            [PSCustomObject]@{ Success = $true; Error = $null; Data = (New-NvmeIdentify) }
        }

        $r = Get-DiskMediaType -DiskNumber 0

        $r.SupportsSecureErase | Should -BeFalse
        $r.SanitizeCapability.DeviceAnswered | Should -BeTrue
    }
}

Describe 'New-ErasureCertificate Purge reporting' {

    BeforeAll {
        $Script:CertDir = Join-Path $env:TEMP ('ed-purge-cert-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -Path $Script:CertDir -ItemType Directory -Force | Out-Null
        $Script:EraseDriveConfig.CertDirectory = $Script:CertDir
        $Script:EraseDriveConfig.Version       = '3.1.0'
        $Script:EraseDriveConfig.EvidenceRoot  = $null

        $Script:VerifiedResult = [PSCustomObject]@{
            Verified = $true; SamplesChecked = 100; SamplesFailed = 0; FinalPattern = 0
        }

        function Get-CertText {
            param($SanitizeCapability)
            $r = New-ErasureCertificate -OperationType 'DiskErase' `
                    -TargetDescription 'Disk 0 (TEST)' `
                    -Method 'Standard (single-pass zero overwrite)' `
                    -DiskSerial 'SN123' -DiskModel 'TESTDISK' -DiskSizeGB 100 `
                    -VerificationResult $Script:VerifiedResult `
                    -SanitizeCapability $SanitizeCapability
            if (-not $r.Success) { throw 'certificate generation failed' }
            Get-Content $r.FilePath -Raw
        }
    }

    AfterAll {
        if ($Script:CertDir -and (Test-Path $Script:CertDir)) {
            Remove-Item $Script:CertDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    BeforeEach { Mock Write-OperationLog {} }

    It 'Never claims Purge was achieved, in ANY capability state' {
        # The cross-product that matters legally. Whatever the device reports, the
        # certificate must not assert that Purge happened, because no code path
        # issues a sanitize command.
        $states = @(
            $null
            [PSCustomObject]@{ PurgeCapable = $true;  DeviceAnswered = $true;  Determination = 'Queried';      PurgeMethods = @('NVMe Sanitize, block erase'); Blockers = @() }
            [PSCustomObject]@{ PurgeCapable = $false; DeviceAnswered = $true;  Determination = 'Queried';      PurgeMethods = @();                            Blockers = @() }
            [PSCustomObject]@{ PurgeCapable = $false; DeviceAnswered = $false; Determination = 'NotAttempted'; PurgeMethods = @();                            Blockers = @('USB bridge.') }
            [PSCustomObject]@{ PurgeCapable = $null;  DeviceAnswered = $false; Determination = 'QueryFailed';  PurgeMethods = @();                            Blockers = @('No answer.') }
        )

        foreach ($state in $states) {
            $text = Get-CertText -SanitizeCapability $state
            $label = if ($null -eq $state) { 'no capability record' } else { $state.Determination }

            $text | Should -Not -BeLike '*meets NIST SP 800-88 Rev.1 Purge*' -Because "state: $label"
            $text | Should -Not -BeLike '*Purge achieved*'                   -Because "state: $label"
            # Clear is still asserted, because it was actually performed and verified.
            $text | Should -BeLike '*meets NIST SP 800-88 Rev.1 Clear*'      -Because "state: $label"
        }
    }

    It 'Names the specific commands when the device reports Purge support' {
        $cap = [PSCustomObject]@{
            PurgeCapable = $true; DeviceAnswered = $true; Determination = 'Queried'
            PurgeMethods = @('NVMe Sanitize, block erase', 'NVMe Format NVM, SES=1 user data erase')
            Blockers     = @()
        }
        $text = Get-CertText -SanitizeCapability $cap

        $text | Should -BeLike '*AVAILABLE ON THIS DEVICE BUT NOT PERFORMED*'
        $text | Should -BeLike '*NVMe Sanitize, block erase*'
        $text | Should -BeLike '*NVMe Format NVM, SES=1 user data erase*'
    }

    It 'Distinguishes UNKNOWN from NOT AVAILABLE' {
        $unknown = [PSCustomObject]@{ PurgeCapable = $null; DeviceAnswered = $false; Determination = 'QueryFailed'
                                      PurgeMethods = @(); Blockers = @('The device did not answer.') }
        $absent  = [PSCustomObject]@{ PurgeCapable = $false; DeviceAnswered = $true; Determination = 'Queried'
                                      PurgeMethods = @(); Blockers = @() }

        $unknownText = Get-CertText -SanitizeCapability $unknown
        $absentText  = Get-CertText -SanitizeCapability $absent

        $unknownText | Should -BeLike '*UNKNOWN*'
        $unknownText | Should -BeLike '*NOT the same as absent*'
        $absentText  | Should -BeLike '*not available on this device*'
        $absentText  | Should -Not -BeLike '*UNKNOWN*'
    }

    It 'Falls back to a generic statement when no capability record is supplied' {
        $text = Get-CertText -SanitizeCapability $null
        $text | Should -BeLike '*capability was not queried*'
    }
}

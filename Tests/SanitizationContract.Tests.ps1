#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

<#
.SYNOPSIS
    The contract between what an erase WRITES and what verification EXPECTS.

.DESCRIPTION
    On 2026-09-09 the first real destructive run showed the default method emitting
    a Certificate of Destruction reading "Status: FAILED" while claiming NIST
    SP 800-88 Clear compliance. Measured: 2370 of 2404 sampled sectors failed, on a
    114.6 GB disk, in 6.7 seconds.

    The cause was one fact living in two files with no channel between them.
    `Invoke-SecureDiskErase` decided what to write; `Test-EraseVerification` decided
    what to expect, from its own independent default of 0x00. Nothing made them
    agree, and across the method/media cross-product they mostly did not:

        Standard, any media   wrote NOTHING              verifier expected 0x00  FAIL
        Secure,   HDD         final pass RANDOM          verifier expected 0x00  FAIL
        Secure,   SSD         diskpart clean all (0x00)  verifier expected 0x00  pass

    The existing 84-test suite could not see any of it, because every one of those
    tests mocks `Test-EraseVerification` to return `Verified = $true`. Mocking the
    component that judges correctness means nothing ever checks the judgement.

    So these tests never mock the verifier's verdict. They capture the arguments it
    is actually handed and compare them against what the method actually wrote.
    Every test here fails against the code as it stood before that date.

.NOTES
    Run with:  Invoke-Pester -Path .\Tests\SanitizationContract.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:repoRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:modulePath = Join-Path $script:repoRoot 'EraseDrive'

    $Script:EraseDriveConfig = @{
        LogDirectory  = Join-Path $TestDrive 'Logs'
        LogFile       = Join-Path (Join-Path $TestDrive 'Logs') 'EraseDrive.log'
        CertDirectory = Join-Path $TestDrive 'Certs'
        LicensePath   = Join-Path $TestDrive 'license.lic'
        PublicKeyPath = Join-Path $TestDrive 'no-such-key.xml'
        MaxLogSizeMB  = 1
        MaxLogFiles   = 3
        Version       = '3.1.0'
        ModuleRoot    = $script:modulePath
        EvidenceRoot  = $null
    }
    New-Item -Path $Script:EraseDriveConfig.LogDirectory -ItemType Directory -Force | Out-Null
    New-Item -Path $Script:EraseDriveConfig.CertDirectory -ItemType Directory -Force | Out-Null

    Get-ChildItem (Join-Path $script:modulePath 'Private') -Filter '*.ps1' | ForEach-Object { . $_.FullName }
    Get-ChildItem (Join-Path $script:modulePath 'Public')  -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}

# ============================================================================
#  1. The overwrite engine must leave the disk in a state sampling can predict
# ============================================================================

Describe 'Invoke-SecureOverwrite: the final pass must be verifiable' {

    BeforeAll {
        $script:overwriteSource = Get-Content -Raw (
            Join-Path $script:modulePath 'Private\Invoke-SecureOverwrite.ps1')
    }

    It 'does not end its default sequence on a random pass' {
        # A random final pass cannot be verified by sampling, which is what made
        # Secure-on-HDD fail its own verification every single time. NIST SP 800-88
        # Rev.1 section 4.7 makes verification part of sanitization, so an
        # unverifiable result is not an acceptable default.
        if ($script:overwriteSource -notmatch "\`$defaults\s*=\s*@\(([^)]*)\)") {
            throw 'Could not locate the default pass sequence.'
        }
        $defaults = $Matches[1]
        $last = ($defaults -split ',')[-1].Trim().Trim("'").Trim('"')

        $last | Should -Not -Be 'RANDOM'
        $last | Should -Match '^0x[0-9A-Fa-f]{1,2}$'
    }

    It 'declares FinalPattern in its documented output' {
        $script:overwriteSource | Should -Match 'FinalPattern'
    }

    It 'returns FinalPattern on every exit path' {
        # Three returns: the zero-byte early exit, the normal completion, and the
        # catch. A missing one hands the caller $null-by-absence, which is
        # indistinguishable from a deliberate "unverifiable" and would silently
        # disable verification.
        $returns  = ([regex]::Matches($script:overwriteSource, 'Success\s+=')).Count
        $patterns = ([regex]::Matches($script:overwriteSource, 'FinalPattern\s+=')).Count
        $patterns | Should -BeGreaterOrEqual $returns
    }
}

# ============================================================================
#  1b. The overwrite engine must survive a disk bigger than Int32
# ============================================================================

Describe 'Invoke-SecureOverwrite: large-disk arithmetic and honest success' {

    BeforeAll {
        $script:overwriteSource = Get-Content -Raw (
            Join-Path $script:modulePath 'Private\Invoke-SecureOverwrite.ps1')
    }

    It 'computes a write length for a 114.6 GB disk without overflowing' {
        # The exact arithmetic that threw on the real SanDisk:
        #   Cannot convert argument "val2", with value: "123041963520", for "Min"
        #   to type "System.Int32"
        # PowerShell selects the [Math]::Min overload from the FIRST argument, so an
        # Int32 buffer length picks Min(int,int) and then fails to convert a
        # multi-gigabyte remainder. Every disk over 2 GB threw on iteration one.
        $totalBytes = [int64]123041963520
        $buffer     = [byte[]]::new(1MB)
        $written    = [int64]0

        { [int64][Math]::Min([int64]$buffer.Length, [int64]($totalBytes - $written)) } |
            Should -Not -Throw

        $writeLen = [int64][Math]::Min([int64]$buffer.Length, [int64]($totalBytes - $written))
        $writeLen | Should -Be 1MB
    }

    It 'clamps the final partial buffer at the end of a large disk' {
        $totalBytes = [int64]123041963520
        $buffer     = [byte[]]::new(1MB)
        $written    = [int64]($totalBytes - 4096)

        $writeLen = [int64][Math]::Min([int64]$buffer.Length, [int64]($totalBytes - $written))
        $writeLen | Should -Be 4096
    }

    It 'does not use the unguarded Min form anywhere' {
        # Regression guard on the shape, because the value that triggers it only
        # appears on hardware no test can safely touch.
        $script:overwriteSource | Should -Not -Match '\[Math\]::Min\(\$buffer\.Length,'
    }

    It 'counts a failed pass as failed, not as completed' {
        # The second half of the defect. The catch block incremented
        # $passesCompleted, so Success = ($passesCompleted -eq $Passes) was $true
        # after a pass wrote zero bytes, and the function reported a successful
        # sanitization of a disk it had never written to.
        $script:overwriteSource | Should -Match '\$passesFailed\+\+'

        if ($script:overwriteSource -notmatch '(?s)catch \{\s*#[^\n]*\n\s*#[^\n]*\n\s*\$passesFailed') {
            # Tolerate comment reflow; the point is the catch must not credit a pass.
            $catchBlocks = [regex]::Matches($script:overwriteSource, '(?s)catch \{.*?\}')
            foreach ($c in $catchBlocks) {
                $c.Value | Should -Not -Match '\$passesCompleted\+\+'
            }
        }
    }

    It 'never fills a buffer one byte at a time' {
        # Measured 2026-09-09: the per-byte PowerShell loop cost 1.985s per 1 MB
        # buffer. Across the 117,342 buffers of a 114.6 GB disk that is 64.7 hours
        # of CPU before a single sector is written, which is why the first real run
        # looked like a hang. Native array operations do the same work in ~0.01s.
        $script:overwriteSource | Should -Not -Match '\$Buffer\[\$i\]\s*=\s*\$byteVal'
        $script:overwriteSource | Should -Not -Match '\$Buffer\[\$i\]\s*=\s*\$patBytes'
        $script:overwriteSource | Should -Match '\[Array\]::Clear'
        $script:overwriteSource | Should -Match '\[Array\]::Copy'
    }

    It 'fills a fixed pattern once per pass, not once per write' {
        # A fixed pattern produces identical bytes every time, so refilling per
        # write was pure waste. Only RANDOM needs regenerating.
        $script:overwriteSource | Should -Match '\$needsRefillEachWrite\s*=\s*\(\$pattern -eq ''RANDOM''\)'
        foreach ($m in [regex]::Matches($script:overwriteSource, '(?m)^\s*(if \(\$needsRefillEachWrite\) \{ )?Fill-Buffer[^
]*$')) {
            # Every call inside a write loop must be guarded; the single unguarded
            # call is the once-per-pass fill.
            $m.Value | Should -Match 'Fill-Buffer'
        }
        ([regex]::Matches($script:overwriteSource, 'if \(\$needsRefillEachWrite\) \{ Fill-Buffer')).Count |
            Should -Be 2 -Because 'both the raw-disk and free-space write loops must be guarded'
    }

    It 'throttles progress to whole-percent changes' {
        # ~117,000 callbacks per pass is wasteful and puts needless script nesting
        # in the hottest loop in the product.
        $script:overwriteSource | Should -Match '\$lastReportedPct'
        $script:overwriteSource | Should -Match '\$pct -ne \$lastReportedPct'
    }

    It 'logs progress directly, not only through the callback' {
        # The callback path is currently unreliable (defect 6). An operator watching
        # a long write needs evidence of movement that does not depend on it.
        $script:overwriteSource | Should -Match "Write-OperationLog[^
]*\`$pct%"
    }

    It 'requires bytes to have reached the media before reporting success' {
        # An overwrite that writes nothing has sanitized nothing, however cleanly
        # its loop exited. This is the invariant that would have caught the whole
        # thing on the very first real run.
        $script:overwriteSource | Should -Match '\$wroteSomething'
        $script:overwriteSource | Should -Match '\$overwriteSucceeded'
    }
}

# ============================================================================
#  1c. "Nothing happened" must never read as "it worked"
#
#  Four of the five defects found on 2026-09-09 were the same shape: a code path
#  that did no work and reported success. They are grouped here because the shape
#  is the bug, not any one instance of it.
# ============================================================================

Describe 'No-op must not report success' {

    BeforeAll {
        $script:overwriteSource = Get-Content -Raw (
            Join-Path $script:modulePath 'Private\Invoke-SecureOverwrite.ps1')
        $script:verifySource = Get-Content -Raw (
            Join-Path $script:modulePath 'Private\Test-EraseVerification.ps1')
    }

    It 'refuses to call an unknown-size physical disk a successful overwrite' {
        # A whole physical disk never legitimately reports 0 bytes. Reaching that
        # branch means the size query failed, so nothing was written and nothing is
        # known. The old code returned Success=$true there, which would have
        # certified a sanitization of a disk it could not even measure.
        $script:overwriteSource | Should -Match 'Refusing to report a successful overwrite'
        $script:overwriteSource | Should -Match 'if \(\$isPhysicalDisk\) \{'
    }

    It 'still allows a genuinely empty volume in free-space mode' {
        # The other half of the distinction: a drive letter with no free space
        # really does have nothing to do, and that is not an error. A guard that
        # simply always refuses would pass the test above and be wrong.
        $script:overwriteSource | Should -Match '0 bytes of free space'
    }

    It 'does not count an unreadable sector as a verified sector' {
        # Test-EraseVerification compared $bytesRead bytes against the expected
        # pattern, having seeded $match = $true. A read returning 0 bytes skipped
        # the loop entirely and was counted as PASSED: an unreadable sector taken
        # as proof of erasure.
        $script:verifySource | Should -Match '\$match = \(\$bytesRead -gt 0\)'
        $script:verifySource | Should -Not -Match '(?m)^\s*\$match = \$true\s*$'
    }
}

# ============================================================================
#  2. What the method writes is what verification is told to expect
# ============================================================================

Describe 'Invoke-SecureDiskErase: write/verify contract' {

    BeforeAll {
        Mock Write-OperationLog { }
        Mock Write-AuditLog { }
    }

    BeforeEach {
        $script:mediaType    = 'HDD'
        $script:protocol     = 'SATA'

        Mock Test-DiskSafeToErase { [PSCustomObject]@{ Safe = $true; Reason = 'ok' } }
        Mock Get-DiskMediaType {
            [PSCustomObject]@{
                MediaType           = $script:mediaType
                SupportsSecureErase = $false
                SupportsTrim        = $false
                Protocol            = $script:protocol
            }
        }
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage', 'HealthStatus', 'VirtualDisk' {
            @([PSCustomObject]@{ DeviceId = '1'; SerialNumber = 'S1'; FriendlyName = 'Test Disk' })
        }
        # Every property the reformat path reads must be present: an ABSENT
        # LargestFreeExtent compares as $null -le 0, which is $true.
        Mock Get-Disk   { [PSCustomObject]@{ Number = 1; Size = 100GB; PartitionStyle = 'RAW'; LargestFreeExtent = 100GB; AllocatedSize = 0 } }
        Mock Update-HostStorageCache { }
        Mock Clear-Disk { }

        # The overwrite engine's real contract, reproduced: the byte it reports is
        # the last one in the sequence it was asked to write.
        Mock Invoke-SecureOverwrite {
            $seq = if ($PassPattern) { $PassPattern } else { @('0x00', '0xFF', '0x00')[0..($Passes - 1)] }
            if ($Passes -gt 0 -and -not $PassPattern) { $seq = @($seq); $seq[$Passes - 1] = '0x00' }
            $last = @($seq)[-1]
            $fp = if ($last -eq 'RANDOM') { $null } else { [byte][Convert]::ToInt32(($last -replace '^0x', ''), 16) }
            [PSCustomObject]@{
                Success          = $true
                BytesOverwritten = 100GB
                PassesCompleted  = $Passes
                Duration         = [timespan]::FromMinutes(1)
                Message          = 'ok'
                FinalPattern     = $fp
            }
        }

        # The verdict is not the thing under test. What matters is the ARGUMENT it
        # is handed, asserted below with -ParameterFilter.
        Mock Test-EraseVerification {
            [PSCustomObject]@{
                Verified = $true; SamplesChecked = 100; SamplesPassed = 100
                SamplesFailed = 0; FailedOffsets = @()
                Duration = [timespan]::FromSeconds(1); Message = 'ok'
            }
        }

        Mock New-ErasureCertificate {
            [PSCustomObject]@{
                CertificateId = [guid]::NewGuid()
                FilePath      = Join-Path $Script:EraseDriveConfig.CertDirectory 'c.txt'
                PdfFilePath   = $null; LicenseTier = 'Free'; Success = $true
            }
        }
        Mock Initialize-Disk { }
        Mock New-Partition   { [PSCustomObject]@{ DiskNumber = 1; PartitionNumber = 2; DriveLetter = 'E' } }
        Mock Format-Volume   { }
        Mock Get-Partition   { @([PSCustomObject]@{ DiskNumber = 1; DriveLetter = 'E' }) }
    }

    It 'Standard actually overwrites the media' {
        # The whole defect in one assertion. Before the fix Standard ran Clear-Disk
        # and returned, so this was zero.
        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false
        Should -Invoke Invoke-SecureOverwrite -Times 1 -Exactly
    }

    It 'Standard verifies against the byte it wrote' {
        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false

        Should -Invoke Test-EraseVerification -Times 1 -Exactly -ParameterFilter {
            $ExpectedPattern -eq [byte]0x00
        }
    }

    It 'carries a NON-zero written pattern through to the verifier' {
        # The decisive test. Every real path currently ends on zeros, which is also
        # the verifier's own default, so a value of 0x00 arriving at the verifier
        # proves nothing: hardcoding it would look identical. Make the overwrite
        # report 0xFF and the two implementations separate. Code that hardcodes
        # 0x00, or that leans on the verifier's default, fails here and only here.
        Mock Invoke-SecureOverwrite {
            [PSCustomObject]@{
                Success          = $true
                BytesOverwritten = 100GB
                PassesCompleted  = $Passes
                Duration         = [timespan]::FromMinutes(1)
                Message          = 'ok'
                FinalPattern     = [byte]0xFF
            }
        }

        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false

        Should -Invoke Test-EraseVerification -Times 1 -Exactly -ParameterFilter {
            $ExpectedPattern -eq [byte]0xFF
        }
    }

    It 'fails the whole erase when the overwrite reports failure' {
        # Before the fix the engine could return Success=$true after writing 0
        # bytes. Now that it reports failure honestly, the erase must treat that as
        # fatal rather than carrying on to verify and certify an untouched disk.
        Mock Invoke-SecureOverwrite {
            [PSCustomObject]@{
                Success          = $false
                BytesOverwritten = [int64]0
                PassesCompleted  = 0
                PassesFailed     = 1
                Duration         = [timespan]::FromSeconds(1)
                Message          = 'Secure overwrite FAILED: 0 of 123041963520 bytes written.'
                FinalPattern     = $null
            }
        }

        $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

        $result.Success     | Should -BeFalse
        $result.Verified    | Should -BeFalse
        $result.Reformatted | Should -BeFalse
        Should -Invoke Test-EraseVerification -Times 0
    }

    It 'skips verification, with a reason, when the media was left unpredictable' {
        # FinalPattern $null means an incomplete run or a random final pass. Sampling
        # cannot confirm that, so verification must be skipped and SAID to be
        # skipped, never run against a guessed pattern and reported as a failure.
        Mock Invoke-SecureOverwrite {
            [PSCustomObject]@{
                Success          = $true
                BytesOverwritten = 100GB
                PassesCompleted  = $Passes
                Duration         = [timespan]::FromMinutes(1)
                Message          = 'ok'
                FinalPattern     = $null
            }
        }

        $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false

        Should -Invoke Test-EraseVerification -Times 0
        $result.Verified | Should -BeFalse
    }

    It 'verification runs even though the written pattern 0x00 is falsy' {
        # $finalPattern is a [byte]. 0x00 is the commonest legitimate value and it
        # is falsy, so a truthiness guard would skip verification on precisely the
        # runs that matter. This pins the $null-versus-zero distinction.
        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false
        Should -Invoke Test-EraseVerification -Times 1 -Exactly
    }

    It 'Secure on rotational media verifies against its real final pass' -ForEach @(
        @{ Media = 'HDD';     Proto = 'SATA' }
        @{ Media = 'Unknown'; Proto = 'SATA' }
        @{ Media = 'Unknown'; Proto = 'USB'  }
    ) {
        # This is the combination that silently failed forever: a multi-pass run
        # whose last pass was random, checked against 0x00.
        $script:mediaType = $Media
        $script:protocol  = $Proto

        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Secure -Confirm:$false

        Should -Invoke Test-EraseVerification -Times 1 -Exactly -ParameterFilter {
            $ExpectedPattern -eq [byte]0x00
        }
    }

    It 'verifies against the written pattern across the method and media matrix' -ForEach @(
        @{ Method = 'Standard'; Media = 'HDD';     Proto = 'SATA' }
        @{ Method = 'Secure';   Media = 'HDD';     Proto = 'SATA' }
        @{ Method = 'Secure';   Media = 'Unknown'; Proto = 'USB'  }
    ) {
        # Asserting the invariant over a cross-product rather than one illustrative
        # case, because one case is what let this survive.
        $script:mediaType = $Media
        $script:protocol  = $Proto

        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod $Method -Confirm:$false

        Should -Invoke Test-EraseVerification -Times 1 -Exactly -ParameterFilter {
            $ExpectedPattern -eq [byte]0x00
        }
    }
}

# ============================================================================
#  3. Quick sanitizes nothing, and must never pretend otherwise
# ============================================================================

Describe 'Quick: honest about doing nothing' {

    BeforeAll {
        Mock Write-OperationLog { }
        Mock Write-AuditLog { }
    }

    BeforeEach {
        $script:certMethod = $null
        Mock Test-DiskSafeToErase { [PSCustomObject]@{ Safe = $true; Reason = 'ok' } }
        Mock Get-DiskMediaType {
            [PSCustomObject]@{ MediaType = 'HDD'; SupportsSecureErase = $false; SupportsTrim = $false; Protocol = 'SATA' }
        }
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage', 'HealthStatus', 'VirtualDisk' {
            @([PSCustomObject]@{ DeviceId = '1'; SerialNumber = 'S1'; FriendlyName = 'Test Disk' })
        }
        # Every property the reformat path reads must be present: an ABSENT
        # LargestFreeExtent compares as $null -le 0, which is $true.
        Mock Get-Disk   { [PSCustomObject]@{ Number = 1; Size = 100GB; PartitionStyle = 'RAW'; LargestFreeExtent = 100GB; AllocatedSize = 0 } }
        Mock Update-HostStorageCache { }
        Mock Clear-Disk { }
        Mock Invoke-SecureOverwrite { throw 'Quick must not overwrite anything' }
        Mock Test-EraseVerification { throw 'Quick must not be verified: nothing was written' }
        Mock New-ErasureCertificate {
            $script:certMethod = $Method
            [PSCustomObject]@{
                CertificateId = [guid]::NewGuid()
                FilePath      = Join-Path $Script:EraseDriveConfig.CertDirectory 'c.txt'
                PdfFilePath   = $null; LicenseTier = 'Free'; Success = $true
            }
        }
    }

    It 'writes nothing to the media' {
        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Quick -Confirm:$false
        Should -Invoke Invoke-SecureOverwrite -Times 0
    }

    It 'does not run verification, because there is nothing to verify' {
        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Quick -Confirm:$false
        Should -Invoke Test-EraseVerification -Times 0
    }

    It 'reports Verified=$false and says the data is still recoverable' {
        $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Quick -Confirm:$false
        $result.Success  | Should -BeTrue
        $result.Verified | Should -BeFalse
        $result.Message  | Should -Match 'recoverable'
        $result.Message  | Should -Match 'not a sanitization'
    }

    It 'labels the method on the certificate as not being a sanitization' {
        $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Quick -Confirm:$false
        $script:certMethod | Should -Match 'NOT a sanitization'
    }

    It 'never reformats, because the reformat gate needs a verified erase' {
        Mock Initialize-Disk { throw 'must not initialize' }
        Mock New-Partition   { throw 'must not partition' }
        Mock Format-Volume   { throw 'must not format' }

        $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Quick -Reformat -Confirm:$false
        $result.Reformatted | Should -BeFalse
    }
}

# ============================================================================
#  4. The certificate's compliance claim must match what happened
# ============================================================================

Describe 'Certificate compliance language' {

    BeforeAll {
        Mock Write-OperationLog { }

        # Defined here, not at Describe level: a function declared directly in a
        # Describe body runs during Pester 5's discovery phase and is not in scope
        # when the It blocks actually execute.
        function New-Verification {
            param([bool]$Passed)
            [PSCustomObject]@{
                Verified      = $Passed
                SamplesChecked = 100
                SamplesPassed = $(if ($Passed) { 100 } else { 3 })
                SamplesFailed = $(if ($Passed) { 0 } else { 97 })
                FailedOffsets = @()
                Duration      = [timespan]::FromSeconds(1)
                Message       = 'x'
            }
        }
    }

    BeforeEach {
        $Script:EraseDriveConfig.CertDirectory = Join-Path $TestDrive ('Certs-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $Script:EraseDriveConfig.CertDirectory -ItemType Directory -Force | Out-Null
    }

    It 'asserts NIST Clear only when the erase was verified' {
        $r = New-ErasureCertificate -OperationType 'DiskErase' -TargetDescription 'Disk 1' `
            -Method 'Standard' -DiskSerial 'S1' -DiskModel 'M' -DiskSizeGB 100 `
            -VerificationResult (New-Verification $true) -OperatorName 'T\u'
        $text = Get-Content -Raw $r.FilePath
        $text | Should -Match 'meets NIST SP 800-88'
    }

    It 'refuses to assert NIST Clear when verification failed' {
        # The exact document the real run produced: an overwrite whose result was
        # not confirmed must not carry a compliance claim.
        $r = New-ErasureCertificate -OperationType 'DiskErase' -TargetDescription 'Disk 1' `
            -Method 'Standard' -DiskSerial 'S1' -DiskModel 'M' -DiskSizeGB 100 `
            -VerificationResult (New-Verification $false) -OperatorName 'T\u'
        $text = Get-Content -Raw $r.FilePath
        $text | Should -Match 'NOT ESTABLISHED'
        $text | Should -Not -Match 'This erasure meets NIST'
    }

    It 'refuses to assert NIST Clear when verification never ran' {
        $r = New-ErasureCertificate -OperationType 'DiskErase' -TargetDescription 'Disk 1' `
            -Method 'Standard' -DiskSerial 'S1' -DiskModel 'M' -DiskSizeGB 100 `
            -VerificationResult $null -OperatorName 'T\u'
        $text = Get-Content -Raw $r.FilePath
        $text | Should -Match 'NOT ESTABLISHED'
    }

    It 'makes no compliance claim at all for Quick' {
        $r = New-ErasureCertificate -OperationType 'DiskErase' -TargetDescription 'Disk 1' `
            -Method 'Quick (Clear-Disk only, NO overwrite, NOT a sanitization method)' `
            -DiskSerial 'S1' -DiskModel 'M' -DiskSizeGB 100 `
            -VerificationResult $null -OperatorName 'T\u'
        $text = Get-Content -Raw $r.FilePath
        $text | Should -Match 'NO COMPLIANCE CLAIM'
        $text | Should -Match 'remain recoverable'
        $text | Should -Not -Match 'This erasure meets NIST'
    }

    It 'does not describe Standard as a single pass it never performs' {
        $r = New-ErasureCertificate -OperationType 'DiskErase' -TargetDescription 'Disk 1' `
            -Method 'Standard' -DiskSerial 'S1' -DiskModel 'M' -DiskSizeGB 100 `
            -VerificationResult (New-Verification $true) -OperatorName 'T\u'
        $text = Get-Content -Raw $r.FilePath
        $text | Should -Match 'single-pass zero overwrite'
    }
}

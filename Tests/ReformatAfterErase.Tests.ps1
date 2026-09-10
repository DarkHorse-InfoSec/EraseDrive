#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

<#
.SYNOPSIS
    Pester 5.x tests for the optional reformat that follows a verified erase.

.DESCRIPTION
    A finished erase leaves the disk RAW. That is correct, and it is also what made an
    operator who wrote the tool conclude his own USB stick had been bricked. Two things
    came out of that: the completion dialog now says the disk was left raw on purpose,
    and -Reformat optionally brings it back.

    -Reformat adds a WRITE to the destructive path, so these tests are written around the
    gate rather than around the happy path. The invariants that matter:

      1. Nothing is written unless the erase was verified. Laying a fresh filesystem over
         a disk we have not confirmed to be clean would bury residual data under a new
         directory structure and make a later audit harder, not easier.
      2. A failed reformat never turns a successful, verified erase into a failure. The
         data is destroyed and the certificate is valid either way.
      3. The disk identity is re-checked before every write, so a hot-plug between the
         erase and the format cannot land on a different disk.
      4. Every skip names its own reason. Asserting only that a guard refused lets a dead
         guard look tested.

    Actual formatting behaviour is not covered here and cannot be: proving a format
    formats needs a disposable disk. These tests cover gating, ordering, refusal and
    reporting, which is where a write bolted onto a destruction path goes wrong.

.NOTES
    Run with:  Invoke-Pester -Path .\Tests\ReformatAfterErase.Tests.ps1 -Output Detailed
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
    Get-ChildItem (Join-Path $script:modulePath 'Public') -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}

Describe 'Invoke-SecureDiskErase -Reformat' {

    BeforeAll {
        Mock Write-OperationLog { }
        Mock Write-AuditLog { }
    }

    BeforeEach {
        # A 500 GB SATA HDD on disk 1 that is safe to erase, erases cleanly, and verifies.
        # Individual tests override exactly one of these to isolate a single gate.
        $script:diskSizeBytes = 500GB
        $script:currentSerial = 'TESTSERIAL'

        Mock Test-DiskSafeToErase {
            [PSCustomObject]@{ Safe = $true; Reason = 'Disk appears safe to erase.' }
        }

        Mock Get-DiskMediaType {
            [PSCustomObject]@{
                MediaType           = 'HDD'
                SupportsSecureErase = $false
                SupportsTrim        = $false
                Protocol            = 'SATA'
            }
        }

        # Reads the script-scoped serial every call, so a test can simulate a hot-plug
        # part way through the operation.
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage', 'HealthStatus', 'VirtualDisk' {
            @([PSCustomObject]@{
                DeviceId     = '1'
                SerialNumber = $script:currentSerial
                FriendlyName = 'Test HDD Model'
            })
        }

        # A freshly erased disk: RAW, nothing allocated, all of it free. Every
        # property the reformat reads must be present, because an ABSENT
        # LargestFreeExtent compares as $null -le 0, which is $true in PowerShell
        # and would trip the no-free-extent guard in every test.
        Mock Get-Disk {
            [PSCustomObject]@{
                Number            = 1
                Size              = $script:diskSizeBytes
                PartitionStyle    = 'RAW'
                LargestFreeExtent = $script:diskSizeBytes
                AllocatedSize     = 0
            }
        }

        Mock Clear-Disk { }

        Mock Invoke-SecureOverwrite {
            [PSCustomObject]@{
                Success          = $true
                BytesOverwritten = $script:diskSizeBytes
                PassesCompleted  = 3
                Duration         = [timespan]::FromMinutes(30)
                Message          = 'Overwrite complete'
                FinalPattern     = [byte]0x00
            }
        }

        Mock Test-EraseVerification {
            [PSCustomObject]@{
                Verified       = $true
                SamplesChecked = 100
                SamplesPassed  = 100
                SamplesFailed  = 0
                FailedOffsets  = @()
                Duration       = [timespan]::FromSeconds(10)
                Message        = 'Verification complete'
            }
        }

        Mock New-ErasureCertificate {
            [PSCustomObject]@{
                CertificateId = [guid]::NewGuid()
                FilePath      = Join-Path $Script:EraseDriveConfig.CertDirectory 'DiskCert.txt'
                PdfFilePath   = $null
                LicenseTier   = 'Free'
                Success       = $true
            }
        }

        # The writes the reformat performs, plus the layout normalization that now
        # precedes them.
        Mock Update-HostStorageCache { }
        Mock Initialize-Disk { }
        Mock New-Partition {
            [PSCustomObject]@{
                DiskNumber      = 1
                PartitionNumber = 2
                DriveLetter     = 'E'
            }
        }
        Mock Format-Volume { }
        Mock Get-Partition {
            @([PSCustomObject]@{ DiskNumber = 1; PartitionNumber = 2; DriveLetter = 'E' })
        }
    }

    # ── Default: off ─────────────────────────────────────────────────────────

    Context 'when -Reformat is not specified' {

        It 'writes nothing back to the disk' {
            $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false

            Should -Invoke Initialize-Disk -Times 0
            Should -Invoke New-Partition  -Times 0
            Should -Invoke Format-Volume  -Times 0
        }

        It 'reports Reformatted=$false with no reformat message' {
            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false

            $result.Success        | Should -BeTrue
            $result.Reformatted    | Should -BeFalse
            $result.ReformatMessage | Should -BeNullOrEmpty
            $result.DriveLetter    | Should -BeNullOrEmpty
        }

        It 'says in the summary that the disk was deliberately left raw' {
            # The operator-facing half of the bug: silence here reads as a bricked disk.
            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false
            $result.Message | Should -Match 'left raw'
        }
    }

    # ── The happy path ───────────────────────────────────────────────────────

    Context 'when -Reformat is specified and the erase verifies' {

        It 'initializes, partitions and formats exactly once each' {
            $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke Initialize-Disk -Times 1 -Exactly
            Should -Invoke New-Partition  -Times 1 -Exactly
            Should -Invoke Format-Volume  -Times 1 -Exactly
        }

        It 'reports Reformatted=$true and the assigned drive letter' {
            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            $result.Success     | Should -BeTrue
            $result.Verified    | Should -BeTrue
            $result.Reformatted | Should -BeTrue
            $result.DriveLetter | Should -Be 'E'
        }

        It 'defaults to NTFS, GPT and the label ERASED' {
            $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke Initialize-Disk -Times 1 -Exactly -ParameterFilter {
                $PartitionStyle -eq 'GPT'
            }
            Should -Invoke Format-Volume -Times 1 -Exactly -ParameterFilter {
                $FileSystem -eq 'NTFS' -and $NewFileSystemLabel -eq 'ERASED' -and "$DriveLetter" -eq 'E'
            }
        }

        It 'passes a caller-chosen filesystem, partition style and label straight through' {
            $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat `
                -ReformatFileSystem 'exFAT' -ReformatPartitionStyle 'MBR' -ReformatLabel 'RECOVERED' -Confirm:$false

            Should -Invoke Initialize-Disk -Times 1 -Exactly -ParameterFilter {
                $PartitionStyle -eq 'MBR'
            }
            Should -Invoke Format-Volume -Times 1 -Exactly -ParameterFilter {
                $FileSystem -eq 'exFAT' -and $NewFileSystemLabel -eq 'RECOVERED'
            }
        }

        It 'creates a single full-size partition rather than sizing it by hand' {
            $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke New-Partition -Times 1 -Exactly -ParameterFilter {
                $DiskNumber -eq 1 -and $UseMaximumSize -and $AssignDriveLetter
            }
        }

        It 'records the reformat on the certificate so an auditor sees who wrote the filesystem' {
            $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke New-ErasureCertificate -Times 1 -Exactly -ParameterFilter {
                $Method -match 'reformatted as NTFS after verification'
            }
        }

        It 'still reports the drive letter when Windows assigns it late' {
            # New-Partition can return before the letter settles; the code re-reads it.
            Mock New-Partition {
                [PSCustomObject]@{ DiskNumber = 1; PartitionNumber = 2; DriveLetter = [char]0 }
            }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            $result.Reformatted | Should -BeTrue
            $result.DriveLetter | Should -Be 'E'
            Should -Invoke Format-Volume -Times 1 -Exactly -ParameterFilter { "$DriveLetter" -eq 'E' }
        }

        It 'breaks a phantom layout with diskpart rather than trusting Clear-Disk' {
            # Measured on real hardware 2026-09-09/10. After zeroing all 114.6 GB,
            # Windows reported PartitionStyle MBR with a full-disk FAT16 partition
            # at offset 0 and LargestFreeExtent 0. Two approaches were tried
            # against that real state and both failed: skipping initialization
            # (New-Partition died with "Not enough available capacity"), and
            # Clear-Disk (the partition API cannot delete a partition that does not
            # really exist, and Initialize-Disk then refused with "The disk has
            # already been initialized"). Only diskpart clean + convert worked.
            $script:phantomBroken = $false
            Mock Get-Disk {
                if ($script:phantomBroken) {
                    [PSCustomObject]@{ Number = 1; Size = $script:diskSizeBytes; PartitionStyle = 'GPT'; LargestFreeExtent = $script:diskSizeBytes; AllocatedSize = 0 }
                }
                else {
                    [PSCustomObject]@{ Number = 1; Size = $script:diskSizeBytes; PartitionStyle = 'MBR'; LargestFreeExtent = 0; AllocatedSize = $script:diskSizeBytes }
                }
            }
            Mock Start-Sleep { }
            # Stand in for diskpart. Invoking the real one in a test would be a
            # destructive command against whatever disk 1 happens to be.
            Mock diskpart { $script:phantomBroken = $true; 'DiskPart succeeded in cleaning the disk.'; $global:LASTEXITCODE = 0 }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke diskpart      -Times 1 -Exactly
            Should -Invoke New-Partition -Times 1 -Exactly
            $result.Reformatted | Should -BeTrue
        }

        It 'does not reach for diskpart when the disk is simply raw' {
            # The ordinary case must stay ordinary. A guard that always shells out
            # would pass the test above and be wrong.
            Mock diskpart { throw 'diskpart must not run for a plainly raw disk' }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke Initialize-Disk -Times 1 -Exactly
            Should -Invoke diskpart        -Times 0
            $result.Reformatted | Should -BeTrue
        }

        It 'refreshes the cached layout before reading it' {
            $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false
            Should -Invoke Update-HostStorageCache -Times 1
        }

        It 'names the real reason when there is genuinely no free extent' {
            # A bare "Not enough available capacity" from New-Partition tells an
            # operator nothing. If the disk still reports no room after diskpart
            # has rewritten the table, say exactly that.
            Mock Get-Disk {
                [PSCustomObject]@{ Number = 1; Size = $script:diskSizeBytes; PartitionStyle = 'GPT'; LargestFreeExtent = 0; AllocatedSize = $script:diskSizeBytes }
            }
            Mock Start-Sleep { }
            Mock diskpart { 'DiskPart succeeded in cleaning the disk.'; $global:LASTEXITCODE = 0 }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke New-Partition -Times 0
            $result.Success         | Should -BeTrue
            $result.Reformatted     | Should -BeFalse
            $result.ReformatMessage | Should -Match 'no free extent'
        }

        It 'reports a diskpart failure instead of pressing on' {
            Mock Get-Disk {
                [PSCustomObject]@{ Number = 1; Size = $script:diskSizeBytes; PartitionStyle = 'MBR'; LargestFreeExtent = 0; AllocatedSize = $script:diskSizeBytes }
            }
            Mock Start-Sleep { }
            Mock diskpart { 'Virtual Disk Service error'; $global:LASTEXITCODE = 1 }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke New-Partition -Times 0
            $result.Success         | Should -BeTrue
            $result.Reformatted     | Should -BeFalse
            $result.ReformatMessage | Should -Match 'diskpart could not rewrite'
        }

        It 'refuses to format when no drive letter was assigned at all' {
            # Formatting is addressed by drive letter. With no letter there is nothing
            # safe to address, so the partition is left unformatted and said so, rather
            # than the code guessing at a target.
            Mock New-Partition {
                [PSCustomObject]@{ DiskNumber = 1; PartitionNumber = 2; DriveLetter = [char]0 }
            }
            Mock Get-Partition { @() }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke Format-Volume -Times 0
            $result.Success         | Should -BeTrue
            $result.Reformatted     | Should -BeFalse
            $result.DriveLetter     | Should -BeNullOrEmpty
            $result.ReformatMessage | Should -Match 'no drive letter'
            $result.ReformatMessage | Should -Match 'Disk Management'
        }
    }

    # ── The gate. This is the part that matters. ─────────────────────────────

    Context 'when the erase was not verified' {

        It 'refuses to format after -SkipVerification, and says why' {
            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -SkipVerification -Confirm:$false

            Should -Invoke Format-Volume  -Times 0
            Should -Invoke New-Partition  -Times 0
            Should -Invoke Initialize-Disk -Times 0

            $result.Success         | Should -BeTrue
            $result.Reformatted     | Should -BeFalse
            $result.ReformatMessage | Should -Match 'SkipVerification'
        }

        It 'refuses to format when verification failed, and says why' {
            Mock Test-EraseVerification {
                [PSCustomObject]@{
                    Verified       = $false
                    SamplesChecked = 100
                    SamplesPassed  = 60
                    SamplesFailed  = 40
                    FailedOffsets  = @(0, 4096)
                    Duration       = [timespan]::FromSeconds(10)
                    Message        = 'Residual data found'
                }
            }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke Format-Volume -Times 0

            $result.Verified        | Should -BeFalse
            $result.Reformatted     | Should -BeFalse
            $result.ReformatMessage | Should -Match 'verification did not pass'
        }

        It 'refuses to format when verification threw rather than returning a verdict' {
            # An exception inside verification leaves $verified false. That must gate the
            # write exactly as an explicit failure does, not fall through to the format.
            Mock Test-EraseVerification { throw 'Cannot open PhysicalDrive1' }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke Format-Volume -Times 0
            $result.Reformatted     | Should -BeFalse
            $result.ReformatMessage | Should -Match 'verification did not pass'
        }
    }

    Context 'when the requested filesystem cannot hold the disk' {

        It 'refuses FAT32 on a disk larger than 32 GB and names the limit' {
            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat `
                -ReformatFileSystem 'FAT32' -Confirm:$false

            Should -Invoke Format-Volume -Times 0
            $result.Reformatted     | Should -BeFalse
            $result.ReformatMessage | Should -Match 'FAT32'
            $result.ReformatMessage | Should -Match '32 GB'
        }

        It 'allows FAT32 on a disk of 32 GB or less' {
            # The boundary the guard is written against, asserted from the other side so a
            # guard that simply always refuses cannot pass.
            $script:diskSizeBytes = 16GB

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat `
                -ReformatFileSystem 'FAT32' -ReformatLabel 'ERASED' -Confirm:$false

            Should -Invoke Format-Volume -Times 1 -Exactly -ParameterFilter { $FileSystem -eq 'FAT32' }
            $result.Reformatted | Should -BeTrue
        }

        It 'refuses MBR beyond 2 TB and names the limit' {
            $script:diskSizeBytes = 4TB

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat `
                -ReformatPartitionStyle 'MBR' -Confirm:$false

            Should -Invoke Format-Volume -Times 0
            $result.ReformatMessage | Should -Match 'MBR'
            $result.ReformatMessage | Should -Match '2 TB'
        }

        It 'allows GPT beyond 2 TB' {
            $script:diskSizeBytes = 4TB

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke Format-Volume -Times 1 -Exactly
            $result.Reformatted | Should -BeTrue
        }

        It 'refuses a label longer than 11 characters on a non-NTFS volume' {
            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat `
                -ReformatFileSystem 'exFAT' -ReformatLabel 'TWELVECHARSX' -Confirm:$false

            Should -Invoke Format-Volume -Times 0
            $result.ReformatMessage | Should -Match '11'
        }

        It 'allows a long label on NTFS, which permits 32 characters' {
            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat `
                -ReformatLabel 'TWELVECHARSX' -Confirm:$false

            Should -Invoke Format-Volume -Times 1 -Exactly -ParameterFilter { $NewFileSystemLabel -eq 'TWELVECHARSX' }
            $result.Reformatted | Should -BeTrue
        }
    }

    # ── A failed reformat is a degraded outcome, not a failed erase ──────────

    Context 'when the reformat itself fails' {

        It 'keeps Success=$true, because the data is still destroyed' {
            Mock Format-Volume { throw 'The media is write protected.' }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            $result.Success         | Should -BeTrue
            $result.Verified        | Should -BeTrue
            $result.Reformatted     | Should -BeFalse
            $result.ReformatMessage | Should -Match 'write protected'
            # Reporting a letter next to Reformatted=$false would imply a usable volume.
            $result.DriveLetter     | Should -BeNullOrEmpty
        }

        It 'still generates the erasure certificate' {
            Mock New-Partition { throw 'The disk is read only.' }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke New-ErasureCertificate -Times 1 -Exactly
            $result.CertificatePath | Should -Not -BeNullOrEmpty
        }

        It 'does not claim the reformat happened on the certificate when it did not' {
            Mock Initialize-Disk { throw 'Access is denied.' }

            $null = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke New-ErasureCertificate -Times 1 -Exactly -ParameterFilter {
                $Method -notmatch 'reformatted'
            }
        }
    }

    # ── Hot-plug safety ──────────────────────────────────────────────────────

    Context 'when the disk changes identity between the erase and the format' {

        It 'aborts the reformat rather than formatting a different disk' {
            # Swap the serial the moment the partition is created. The identity assertion
            # that runs before Format-Volume must catch it.
            Mock New-Partition {
                $script:currentSerial = 'A-COMPLETELY-DIFFERENT-DISK'
                [PSCustomObject]@{ DiskNumber = 1; PartitionNumber = 2; DriveLetter = 'E' }
            }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke Format-Volume -Times 0
            $result.Reformatted     | Should -BeFalse
            $result.ReformatMessage | Should -Match 'SAFETY ABORT'
        }

        It 'aborts before creating a partition when the disk changes during verification' {
            Mock Test-EraseVerification {
                $script:currentSerial = 'A-COMPLETELY-DIFFERENT-DISK'
                [PSCustomObject]@{
                    Verified       = $true
                    SamplesChecked = 100
                    SamplesPassed  = 100
                    SamplesFailed  = 0
                    FailedOffsets  = @()
                    Duration       = [timespan]::FromSeconds(10)
                    Message        = 'Verification complete'
                }
            }

            $result = Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -Confirm:$false

            Should -Invoke New-Partition -Times 0
            Should -Invoke Format-Volume -Times 0
            $result.ReformatMessage | Should -Match 'SAFETY ABORT'
        }
    }

    # ── -WhatIf ──────────────────────────────────────────────────────────────

    Context 'under -WhatIf' {

        It 'writes nothing, reformat requested or not' {
            Mock Initialize-Disk { throw 'Initialize-Disk must not run under -WhatIf' }
            Mock New-Partition   { throw 'New-Partition must not run under -WhatIf' }
            Mock Format-Volume { throw 'Format-Volume must not run under -WhatIf' }
            Mock Clear-Disk      { throw 'Clear-Disk must not run under -WhatIf' }

            { Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Reformat -WhatIf } | Should -Not -Throw

            Should -Invoke Initialize-Disk -Times 0
            Should -Invoke New-Partition   -Times 0
            Should -Invoke Format-Volume   -Times 0
        }
    }

    # ── Shape ────────────────────────────────────────────────────────────────

    Context 'result shape' {

        It 'carries the reformat properties on every exit path' -ForEach @(
            @{ Path = 'success' }
            @{ Path = 'safety-abort' }
            @{ Path = 'cancelled' }
            @{ Path = 'error' }
        ) {
            # A consumer that reads $result.Reformatted must not have to know which exit
            # path produced the object. This repo has already shipped two bugs from one
            # fact living in two places; a divergent result shape is the same failure.
            switch ($Path) {
                'safety-abort' {
                    Mock Test-DiskSafeToErase {
                        [PSCustomObject]@{ Safe = $false; Reason = 'This is the system disk.' }
                    }
                }
                'cancelled' { }
                'error'     { Mock Clear-Disk { throw 'Device not ready.' } }
            }

            $result = if ($Path -eq 'cancelled') {
                Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -WhatIf
            }
            else {
                Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Standard -Confirm:$false
            }

            if ($Path -eq 'cancelled') {
                # -WhatIf returns the cancellation object; guard against a null result
                # silently passing the property assertions below.
                $result | Should -Not -BeNullOrEmpty
            }

            $result.PSObject.Properties.Name | Should -Contain 'Reformatted'
            $result.PSObject.Properties.Name | Should -Contain 'ReformatMessage'
            $result.PSObject.Properties.Name | Should -Contain 'DriveLetter'
        }
    }
}

# ============================================================================
#  Wiring
#
#  The reformat switch and the raw-disk explanation each live in three places:
#  the function, the GUI and the CLI launcher. The one recurring defect in this
#  repo is a fact updated in one home and not the others, so assert the wiring
#  at source level rather than trusting that all three were remembered.
# ============================================================================

Describe 'Reformat wiring across the three entry points' {

    BeforeAll {
        $script:guiSource = Get-Content -Raw (Join-Path $script:modulePath 'Public\Start-EraseDriveGUI.ps1')
        $script:cliSource = Get-Content -Raw (Join-Path $script:repoRoot 'Start-EraseDrive.ps1')
    }

    It 'the GUI offers a reformat checkbox that is off by default' {
        $script:guiSource | Should -Match '\$chkReformat\s*=\s*New-Object System\.Windows\.Forms\.CheckBox'
        $script:guiSource | Should -Match '\$chkReformat\.Checked\s*=\s*\$false'
    }

    It 'the GUI checkbox is actually added to the form' {
        # A control that is created but never added to Controls is invisible, which is
        # exactly how the license tier badge was lost once already.
        $script:guiSource | Should -Match '\$chkClearLogs,\s*\$chkReformat'
    }

    It 'the GUI passes the checkbox through to Invoke-SecureDiskErase' {
        $script:guiSource | Should -Match 'Invoke-SecureDiskErase[^\r\n]*-Reformat:\$doReformat'
    }

    It 'the GUI disables the checkbox while an operation is running' {
        $script:guiSource | Should -Match '\$chkReformat\.Enabled\s*=\s*\$false'
        $script:guiSource | Should -Match '\$chkReformat\.Enabled\s*=\s*\$true'
    }

    It 'the GUI completion dialog explains the raw disk instead of leaving it a mystery' {
        $script:guiSource | Should -Match 'THE DISK IS NOW RAW'
        $script:guiSource | Should -Match 'diskmgmt\.msc'
    }

    It 'the CLI exposes -Reformat and passes it through' {
        $script:cliSource | Should -Match '\[switch\]\$Reformat'
        $script:cliSource | Should -Match 'Invoke-SecureDiskErase[^\r\n]*-Reformat:\$Reformat'
    }

    It 'the GUI reports real progress, not just a marquee' {
        # Standard now performs a full single-pass overwrite, so the default
        # operation went from seconds to tens of minutes. A marquee bar with no
        # numbers is indistinguishable from a hang, which is exactly the failure
        # already flagged for the per-profile step of the user wipe.
        $script:guiSource | Should -Match '\$script:progressState\s*=\s*\[hashtable\]::Synchronized'
        $script:guiSource | Should -Match '-ReportProgress'
        # Both long-running operations must feed it, not just one.
        ([regex]::Matches($script:guiSource, '\$progress\.Percent\s*=')).Count |
            Should -BeGreaterOrEqual 2
    }

    It 'the GUI distinguishes "no progress yet" from "0 percent"' {
        # Percent is seeded to -1. Seeding it to 0 would show a determinate bar
        # pinned at zero before the worker has said anything, which reads as
        # stalled rather than starting.
        $script:guiSource | Should -Match 'Percent\s*=\s*-1'
        $script:guiSource | Should -Match '\$pct -ge 0'
    }

    It 'the GUI worker never touches the form from the background runspace' {
        # A shared hashtable is the only legal channel. Touching a control from the
        # worker runspace throws a cross-thread exception at best.
        foreach ($m in [regex]::Matches($script:guiSource, '(?s)\$script:ps\.AddScript\(\{.*?\}\)\.AddArgument')) {
            $m.Value | Should -Not -Match '\$progressBar|\$lblProgress|\$form'
        }
    }

    It 'the CLI explains the raw disk too' {
        $script:cliSource | Should -Match 'RAW'
        $script:cliSource | Should -Match '-Reformat'
    }
}

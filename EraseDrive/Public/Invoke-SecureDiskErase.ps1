function Invoke-SecureDiskErase {
    <#
    .SYNOPSIS
        Performs complete disk erasure with SSD-aware handling.

    .DESCRIPTION
        Erases the specified disk using the appropriate method for its media type and bus
        protocol. The function first validates the disk is safe to erase (not a system or
        boot disk), then queries hardware characteristics to select the optimal erasure
        strategy.

        Quick removes the partition table with Clear-Disk and writes nothing to the
        media. It is NOT a sanitization method: the data remains on the disk and is
        recoverable with ordinary tools. It exists for repartitioning, produces no
        compliance claim, and is not verified.

        Standard removes the partition table and then overwrites every addressable
        sector once with zeros. That is NIST SP 800-88 Rev.1 Clear, and it is the
        default.

        Secure method applies media-appropriate deep erasure:
        - HDD: Clear-Disk followed by a 3-pass overwrite of the raw physical device
        - SSD (SATA): diskpart 'clean all' via a temporary script file
        - SSD (NVMe): diskpart 'clean all' with NVMe-specific handling logged
        - Fallback: If SSD-specific commands fail, warns that SSD overwrite is unreliable
          due to wear-leveling and over-provisioning, then performs Clear-Disk + overwrite

        Post-erase verification samples sectors to confirm data was destroyed (unless
        -SkipVerification is specified). An erasure certificate is generated upon completion.

        A successful erase removes the partition table along with the data, so the disk is
        left RAW: no partitions, no filesystem, and no drive letter. That is the correct
        end state for a destruction tool and the disk is not damaged. Pass -Reformat to
        have EraseDrive create a single full-size partition and filesystem afterwards, so
        the disk comes back usable. Reformatting runs only after both the erase and its
        verification have succeeded; if either did not, the reformat is skipped and the
        reason is reported in ReformatMessage.

    .PARAMETER DiskNumber
        The disk number to erase (as shown by Get-Disk or Disk Management).

    .PARAMETER EraseMethod
        'Quick' removes partitioning only and writes nothing. NOT sanitization, and
        it makes no compliance claim. 'Standard' (default) removes partitioning and
        overwrites every sector once with zeros: NIST SP 800-88 Rev.1 Clear.
        'Secure' performs media-aware deep erasure, a 3-pass overwrite on rotational
        media or a full-device zero fill on SSDs.

        Note that 'Secure' is not more NIST-compliant than 'Standard'. Both reach
        Clear; the extra passes are there because audit checklists still ask for
        them. Neither reaches Purge on an SSD, which needs the drive's own sanitize
        or crypto-erase command.

    .PARAMETER SkipVerification
        When specified, skips the post-erase sector verification step. Not recommended
        for compliance-sensitive erasures.

    .PARAMETER ReportProgress
        Optional scriptblock callback invoked with progress updates. Receives a hashtable
        with keys: PercentComplete (int), Status (string), CurrentOperation (string).

    .PARAMETER Reformat
        When specified, creates a single full-size partition and filesystem on the disk
        after a successful, verified erase, so the disk is usable again instead of being
        left RAW. Off by default: the safe end state for a destruction tool is a raw disk.

        The reformat is deliberately gated. It is skipped, with a reason, when
        -SkipVerification was passed, when verification did not pass, or when the
        requested filesystem cannot hold the disk. A failed reformat never fails the
        erase: the data is still destroyed and the certificate is still valid.

    .PARAMETER ReformatFileSystem
        Filesystem to create when -Reformat is specified. 'NTFS' (default), 'exFAT' for
        cross-platform removable media, or 'FAT32' for disks of 32 GB or less.

    .PARAMETER ReformatPartitionStyle
        Partition style to initialize when -Reformat is specified. 'GPT' (default) or
        'MBR'. MBR cannot address more than 2 TB.

    .PARAMETER ReformatLabel
        Volume label to apply when -Reformat is specified. Default: 'ERASED'. NTFS allows
        up to 32 characters; exFAT and FAT32 allow up to 11.

    .PARAMETER TimeoutMinutes
        Maximum number of minutes the operation is allowed to run. 0 (default) means no
        timeout. If the timeout is exceeded, the operation aborts gracefully, generates a
        partial certificate noting the timeout, and returns Success=$false.

    .OUTPUTS
        PSCustomObject with properties:
            Success         [bool]     - Whether the erase completed without fatal errors
            Message         [string]   - Summary message
            DiskNumber      [int]      - The disk number that was erased
            Method          [string]   - The erase method used
            Verified        [bool]     - Whether post-erase verification passed
            CertificatePath [string]   - Path to the erasure certificate file
            Reformatted     [bool]     - Whether a new filesystem was created afterwards
            ReformatMessage [string]   - Outcome of the reformat, or why it was skipped
            DriveLetter     [string]   - Drive letter assigned by the reformat, if any
            Duration        [timespan] - Total elapsed time

    .EXAMPLE
        Invoke-SecureDiskErase -DiskNumber 1

        Performs a standard erase of disk 1 with verification and certificate generation.

    .EXAMPLE
        Invoke-SecureDiskErase -DiskNumber 2 -EraseMethod Secure

        Performs a secure media-aware erase of disk 2 with verification.

    .EXAMPLE
        Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Secure -SkipVerification -Confirm:$false

        Performs a secure erase of disk 1 without verification or confirmation prompt.

    .EXAMPLE
        Invoke-SecureDiskErase -DiskNumber 3 -EraseMethod Secure -ReportProgress {
            param($info)
            Write-Progress -Activity 'Disk Erase' -Status $info.Status -PercentComplete $info.PercentComplete
        }

        Performs a secure erase of disk 3 with progress reporting.

    .EXAMPLE
        Invoke-SecureDiskErase -DiskNumber 1 -EraseMethod Secure -Reformat -ReformatFileSystem exFAT -ReformatLabel 'RECOVERED'

        Securely erases disk 1, verifies it, then brings it back as a single exFAT volume
        labelled RECOVERED rather than leaving it raw.

    .EXAMPLE
        Invoke-SecureDiskErase -DiskNumber 1 -WhatIf

        Shows what the erase operation would do without making any changes.

    .NOTES
        Requires Administrator privileges.
        Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [int]$DiskNumber,

        [Parameter()]
        [ValidateSet('Quick', 'Standard', 'Secure')]
        [string]$EraseMethod = 'Standard',

        [Parameter()]
        [switch]$SkipVerification,

        [Parameter()]
        [scriptblock]$ReportProgress,

        [Parameter()]
        [switch]$Reformat,

        [Parameter()]
        [ValidateSet('NTFS', 'exFAT', 'FAT32')]
        [string]$ReformatFileSystem = 'NTFS',

        [Parameter()]
        [ValidateSet('GPT', 'MBR')]
        [string]$ReformatPartitionStyle = 'GPT',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1, 32)]
        [string]$ReformatLabel = 'ERASED',

        [Parameter()]
        [int]$TimeoutMinutes = 0
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $verified = $false
    $certificatePath = $null
    $pdfCertificatePath = $null
    $licenseTier = 'Free'
    $operationLock = $null
    $reformatted = $false
    $reformatMessage = $null
    $reformatDriveLetter = $null

    # The byte this run leaves across the media, and therefore the byte verification
    # must expect. $null means "nothing predictable was written", which is a
    # DIFFERENT state from "zeros were written" even though 0x00 is falsy. Always
    # compare with `$null -eq $finalPattern`; `if ($finalPattern)` is false for the
    # commonest success case and would silently skip verification.
    $finalPattern = $null

    # Helper to invoke the caller's progress callback safely.
    #
    # The name here is deliberate and was learned the hard way.
    #
    # The callback is captured into $callerProgress, a name that exists nowhere
    # else in this module. `$ReportProgress` is the parameter name of BOTH this
    # function and Invoke-SecureOverwrite, and a scriptblock invoked with & from
    # inside the other function resolves that name in the wrong scope: the
    # caller's callback silently never fires. Reproduced in isolation before
    # changing anything.
    #
    # Confirmed working in a real run after the rename: the operator sees
    # "[ 41%] Overwriting disk - Pass 1 of 1" while the overwrite is in flight.
    # Do not rename $callerProgress back to $ReportProgress.
    $callerProgress = $ReportProgress
    $reportStep = {
        param([int]$Percent, [string]$Status, [string]$Operation)
        if ($null -ne $callerProgress) {
            try {
                & $callerProgress @{
                    PercentComplete  = $Percent
                    Status           = $Status
                    CurrentOperation = $Operation
                }
            }
            catch { }
        }
    }

    # Helper to check timeout; returns $true if timed out
    $checkTimeout = {
        if ($TimeoutMinutes -gt 0 -and $stopwatch.Elapsed.TotalMinutes -ge $TimeoutMinutes) {
            return $true
        }
        return $false
    }

    # Helper to handle timeout abort: logs warning, generates partial certificate, returns result
    $handleTimeoutAbort = {
        param([string]$DiskDesc, [string]$MethodDesc, [string]$Serial, [string]$Model, [double]$SizeGB)
        $timeoutMsg = "Operation timed out after $TimeoutMinutes minutes"
        Write-OperationLog -Message "TIMEOUT: $timeoutMsg for disk $DiskNumber" -LogLevel 'WARNING'

        # Generate partial certificate noting timeout
        try {
            $partialCertResult = New-ErasureCertificate `
                -OperationType 'DiskErase' `
                -TargetDescription $DiskDesc `
                -Method "$MethodDesc (PARTIAL - timed out after $TimeoutMinutes minutes)" `
                -DiskSerial $Serial `
                -DiskModel $Model `
                -DiskSizeGB $SizeGB `
                -VerificationResult $null `
                -OperatorName ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

            if ($partialCertResult.Success) {
                $script:certificatePath = $partialCertResult.FilePath
                $script:pdfCertificatePath = $partialCertResult.PdfFilePath
                $script:licenseTier = $partialCertResult.LicenseTier
                Write-OperationLog -Message "Partial erasure certificate generated (timeout): $($partialCertResult.FilePath)" -LogLevel 'WARNING'
                if ($partialCertResult.PdfFilePath) {
                    Write-OperationLog -Message "Partial PDF certificate generated (timeout): $($partialCertResult.PdfFilePath)" -LogLevel 'WARNING'
                }
            }
        }
        catch {
            Write-OperationLog -Message "Failed to generate timeout certificate: $($_.Exception.Message)" -LogLevel 'WARNING'
        }

        $stopwatch.Stop()

        return [PSCustomObject]@{
            Success            = $false
            Message            = $timeoutMsg
            DiskNumber         = $DiskNumber
            Method             = $EraseMethod
            Verified           = $false
            CertificatePath    = $script:certificatePath
            PdfCertificatePath = $script:pdfCertificatePath
            LicenseTier        = $script:licenseTier
            Reformatted        = $reformatted
            ReformatMessage    = $reformatMessage
            DriveLetter        = $reformatDriveLetter
            Duration           = $stopwatch.Elapsed
        }
    }

    try {
        # ── Acquire operation lock ─────────────────────────────────────
        $operationLock = Enter-OperationLock -OperationName 'SecureDiskErase'

        if (-not $operationLock.Acquired) {
            $stopwatch.Stop()
            return [PSCustomObject]@{
                Success            = $false
                Message            = $operationLock.Message
                DiskNumber         = $DiskNumber
                Method             = $EraseMethod
                Verified           = $false
                CertificatePath    = $null
                PdfCertificatePath = $null
                LicenseTier        = $licenseTier
                Reformatted        = $reformatted
                ReformatMessage    = $reformatMessage
                DriveLetter        = $reformatDriveLetter
                Duration           = $stopwatch.Elapsed
            }
        }

        Write-OperationLog -Message "Disk erase initiated: Disk $DiskNumber, Method=$EraseMethod, SkipVerification=$SkipVerification, TimeoutMinutes=$TimeoutMinutes" -LogLevel 'INFO'
        Write-AuditLog -EventType 'OperationStarted' -Message "Disk erase initiated (Method=$EraseMethod, SkipVerification=$SkipVerification)" -TargetDescription "Disk $DiskNumber"
        & $reportStep 0 'Initializing' 'Validating disk safety'

        # ── 1. Safety check ──────────────────────────────────────────────
        $safetyResult = Test-DiskSafeToErase -DiskNumber $DiskNumber

        if (-not $safetyResult.Safe) {
            $msg = "Disk $DiskNumber is not safe to erase: $($safetyResult.Reason)"
            Write-OperationLog -Message $msg -LogLevel 'ERROR'
            Write-AuditLog -EventType 'SafetyAbort' -Message $safetyResult.Reason -TargetDescription "Disk $DiskNumber"
            $stopwatch.Stop()

            return [PSCustomObject]@{
                Success            = $false
                Message            = $msg
                DiskNumber         = $DiskNumber
                Method             = $EraseMethod
                Verified           = $false
                CertificatePath    = $null
                PdfCertificatePath = $null
                LicenseTier        = $licenseTier
                Reformatted        = $reformatted
                ReformatMessage    = $reformatMessage
                DriveLetter        = $reformatDriveLetter
                Duration           = $stopwatch.Elapsed
            }
        }

        Write-OperationLog -Message "Disk $DiskNumber passed safety check: $($safetyResult.Reason)" -LogLevel 'INFO'

        # ── 1b. Pin disk identity to detect hot-plug race conditions ────
        $expectedSerial = (Get-PhysicalDisk | Where-Object { $_.DeviceId -eq "$DiskNumber" }).SerialNumber
        Write-OperationLog -Message "Pinned disk $DiskNumber identity: serial '$expectedSerial'" -LogLevel 'INFO'

        # Helper to verify disk identity has not changed
        $assertDiskIdentity = {
            $currentSerial = (Get-PhysicalDisk | Where-Object { $_.DeviceId -eq "$DiskNumber" }).SerialNumber
            if ($currentSerial -ne $expectedSerial) {
                throw "SAFETY ABORT: Disk $DiskNumber identity changed (expected serial '$expectedSerial', found '$currentSerial'). Possible hot-plug event."
            }
        }

        # ── 2. Get disk information ──────────────────────────────────────
        & $reportStep 5 'Detecting media type' 'Querying disk hardware'

        $diskObj = Get-Disk -Number $DiskNumber -ErrorAction Stop
        $physicalDisk = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $DiskNumber.ToString() } | Select-Object -First 1
        $mediaInfo = Get-DiskMediaType -DiskNumber $DiskNumber

        $mediaType = $mediaInfo.MediaType
        $protocol = $mediaInfo.Protocol
        $diskSerial = $(if ($physicalDisk) { $physicalDisk.SerialNumber } else { 'Unknown' })
        $diskModel = $(if ($physicalDisk) { $physicalDisk.FriendlyName } else { 'Unknown' })
        $diskSizeGB = [math]::Round($diskObj.Size / 1GB, 2)
        $diskDescription = "Disk $DiskNumber ($diskModel, ${diskSizeGB} GB, $mediaType/$protocol, S/N: $diskSerial)"

        Write-OperationLog -Message "Target: $diskDescription" -LogLevel 'INFO'
        Write-OperationLog -Message "Disk ${DiskNumber}: MediaType=$mediaType, Protocol=$protocol, SupportsSecureErase=$($mediaInfo.SupportsSecureErase), SupportsTrim=$($mediaInfo.SupportsTrim)" -LogLevel 'INFO'

        # ── 3. ShouldProcess confirmation ────────────────────────────────
        if (-not $PSCmdlet.ShouldProcess($diskDescription, "$EraseMethod erase (ALL DATA WILL BE DESTROYED)")) {
            $stopwatch.Stop()
            Write-OperationLog -Message 'Disk erase cancelled by user.' -LogLevel 'INFO'

            return [PSCustomObject]@{
                Success            = $false
                Message            = 'Disk erase cancelled by user.'
                DiskNumber         = $DiskNumber
                Method             = $EraseMethod
                Verified           = $false
                CertificatePath    = $null
                PdfCertificatePath = $null
                LicenseTier        = $licenseTier
                Reformatted        = $reformatted
                ReformatMessage    = $reformatMessage
                DriveLetter        = $reformatDriveLetter
                Duration           = $stopwatch.Elapsed
            }
        }

        # ── 4. Perform erasure ───────────────────────────────────────────
        if ($EraseMethod -eq 'Quick') {
            # ── Quick: remove partitioning, write nothing ────────────────
            #
            # This leaves the user data intact and recoverable. It is offered for
            # repartitioning, not for decommissioning, and $finalPattern stays $null
            # so that nothing downstream can verify or certify it as sanitized.

            if (& $checkTimeout) {
                return (& $handleTimeoutAbort $diskDescription 'Quick (Clear-Disk, no overwrite)' $diskSerial $diskModel $diskSizeGB)
            }

            & $reportStep 10 'Removing partitions' 'Clear-Disk (Quick, no overwrite)'
            Write-OperationLog -Message "Executing Clear-Disk for disk $DiskNumber (Quick). NOTE: Quick writes nothing to the media; data remains recoverable." -LogLevel 'WARNING'

            & $assertDiskIdentity
            Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
            Write-OperationLog -Message "Clear-Disk completed for disk $DiskNumber (Quick)" -LogLevel 'SUCCESS'

            & $reportStep 70 'Partitions removed' 'Quick finished (no data was overwritten)'
        }
        elseif ($EraseMethod -eq 'Standard') {
            # ── Standard: Clear-Disk + single-pass zero fill ─────────────
            #
            # The single fixed-pattern pass is what makes this NIST 800-88 Clear.
            # Before 2026-09-09 this branch ran Clear-Disk alone, wrote nothing, and
            # then failed its own verification while the certificate claimed Clear.

            if (& $checkTimeout) {
                return (& $handleTimeoutAbort $diskDescription 'Standard (Clear-Disk + single-pass zero overwrite)' $diskSerial $diskModel $diskSizeGB)
            }

            & $reportStep 10 'Erasing disk' 'Clear-Disk (Standard)'
            Write-OperationLog -Message "Executing Clear-Disk for disk $DiskNumber (Standard)" -LogLevel 'INFO'

            & $assertDiskIdentity
            Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
            Write-OperationLog -Message "Clear-Disk completed for disk $DiskNumber" -LogLevel 'INFO'

            if (& $checkTimeout) {
                return (& $handleTimeoutAbort $diskDescription 'Standard (Clear-Disk + single-pass zero overwrite)' $diskSerial $diskModel $diskSizeGB)
            }

            & $reportStep 20 'Overwriting disk' 'Single-pass zero overwrite of the raw device'
            $targetPath = "\\.\PhysicalDrive$DiskNumber"
            Write-OperationLog -Message "Starting single-pass zero overwrite on $targetPath" -LogLevel 'INFO'

            & $assertDiskIdentity
            $overwriteResult = Invoke-SecureOverwrite -TargetPath $targetPath -Passes 1 -ReportProgress {
                param($info)
                & $reportStep ([int](20 + ($info.PercentComplete * 0.45))) 'Overwriting disk' "Pass $($info.Pass) of $($info.TotalPasses)"
            }

            if ($overwriteResult.Success) {
                $finalPattern = $overwriteResult.FinalPattern
                Write-OperationLog -Message "Standard overwrite completed: $($overwriteResult.BytesOverwritten) bytes, $($overwriteResult.Duration)" -LogLevel 'SUCCESS'
            }
            else {
                Write-OperationLog -Message "Standard overwrite issue: $($overwriteResult.Message)" -LogLevel 'ERROR'
                throw "Single-pass overwrite failed: $($overwriteResult.Message)"
            }

            & $reportStep 70 'Erase complete' 'Standard erase finished'
        }
        else {
            # ── Secure: media-aware deep erase ───────────────────────────

            if ($mediaType -ne 'SSD') {
                # ── HDD or Unknown: Clear-Disk + 3-pass overwrite ────────

                # Timeout check before Clear-Disk
                if (& $checkTimeout) {
                    return (& $handleTimeoutAbort $diskDescription 'Secure (Clear-Disk + 3-pass overwrite)' $diskSerial $diskModel $diskSizeGB)
                }

                & $reportStep 10 'Erasing HDD' 'Clear-Disk + multi-pass overwrite'
                Write-OperationLog -Message "Performing secure HDD erase on disk $DiskNumber (Clear-Disk + 3-pass overwrite)" -LogLevel 'INFO'

                & $assertDiskIdentity
                Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
                Write-OperationLog -Message "Clear-Disk completed for HDD disk $DiskNumber" -LogLevel 'INFO'

                # Timeout check before Invoke-SecureOverwrite
                if (& $checkTimeout) {
                    return (& $handleTimeoutAbort $diskDescription 'Secure (Clear-Disk + 3-pass overwrite)' $diskSerial $diskModel $diskSizeGB)
                }

                & $reportStep 20 'Overwriting HDD' 'Secure overwrite: 3 passes on raw device'
                $targetPath = "\\.\PhysicalDrive$DiskNumber"
                Write-OperationLog -Message "Starting 3-pass secure overwrite on $targetPath" -LogLevel 'INFO'

                & $assertDiskIdentity
                $overwriteResult = Invoke-SecureOverwrite -TargetPath $targetPath -Passes 3 -ReportProgress {
                    param($info)
                    & $reportStep ([int](20 + ($info.PercentComplete * 0.45))) 'Overwriting HDD' "Pass $($info.Pass) of $($info.TotalPasses)"
                }

                if ($overwriteResult.Success) {
                    $finalPattern = $overwriteResult.FinalPattern
                    Write-OperationLog -Message "HDD overwrite completed: $($overwriteResult.BytesOverwritten) bytes, $($overwriteResult.PassesCompleted) passes, $($overwriteResult.Duration)" -LogLevel 'SUCCESS'
                }
                else {
                    Write-OperationLog -Message "HDD overwrite issue: $($overwriteResult.Message)" -LogLevel 'ERROR'
                    throw "Secure overwrite failed: $($overwriteResult.Message)"
                }

                & $reportStep 70 'Overwrite complete' 'Secure HDD erase finished'
            }
            else {
                # ── SSD: diskpart clean all ──────────────────────────────
                $ssdEraseSuccess = $false

                if ($protocol -eq 'SATA') {
                    # ── SATA SSD ─────────────────────────────────────────
                    & $reportStep 10 'Erasing SATA SSD' 'diskpart clean all'
                    Write-OperationLog -Message "Performing SATA SSD secure erase on disk $DiskNumber via diskpart clean all" -LogLevel 'INFO'

                    & $assertDiskIdentity
                    try {
                        $diskpartFile = Join-Path $env:TEMP "erase_disk_$DiskNumber.txt"
                        @(
                            "select disk $DiskNumber"
                            'clean all'
                        ) | Set-Content -Path $diskpartFile -Encoding ASCII -Force

                        Write-OperationLog -Message "Executing diskpart script for SATA SSD disk $DiskNumber" -LogLevel 'INFO'
                        & $reportStep 20 'Running diskpart' 'diskpart clean all (SATA SSD)'

                        $diskpartOutput = & diskpart /s $diskpartFile 2>&1
                        $diskpartExitCode = $LASTEXITCODE

                        Remove-Item $diskpartFile -Force -ErrorAction SilentlyContinue

                        if ($diskpartExitCode -eq 0 -and ($diskpartOutput -join "`n") -match 'succeeded') {
                            $ssdEraseSuccess = $true
                            # 'clean all' zero-fills every sector, so the media is left at 0x00.
                            $finalPattern = [byte]0x00
                            Write-OperationLog -Message "diskpart clean all completed successfully for SATA SSD disk $DiskNumber" -LogLevel 'SUCCESS'
                        }
                        else {
                            $diskpartText = ($diskpartOutput -join "`n").Trim()
                            Write-OperationLog -Message "diskpart clean all did not confirm success (exit: $diskpartExitCode): $diskpartText" -LogLevel 'WARNING'
                        }
                    }
                    catch {
                        Write-OperationLog -Message "diskpart failed for SATA SSD disk ${DiskNumber}: $($_.Exception.Message)" -LogLevel 'WARNING'
                        if (Test-Path $diskpartFile) {
                            Remove-Item $diskpartFile -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                elseif ($protocol -eq 'NVMe') {
                    # ── NVMe SSD ─────────────────────────────────────────
                    & $reportStep 10 'Erasing NVMe SSD' 'diskpart clean all'
                    Write-OperationLog -Message "Performing NVMe SSD secure erase on disk $DiskNumber via diskpart clean all" -LogLevel 'INFO'
                    Write-OperationLog -Message "NVMe drive detected - diskpart clean all will issue sanitize/format commands where supported by the controller" -LogLevel 'INFO'

                    & $assertDiskIdentity
                    try {
                        $diskpartFile = Join-Path $env:TEMP "erase_disk_$DiskNumber.txt"
                        @(
                            "select disk $DiskNumber"
                            'clean all'
                        ) | Set-Content -Path $diskpartFile -Encoding ASCII -Force

                        Write-OperationLog -Message "Executing diskpart script for NVMe SSD disk $DiskNumber" -LogLevel 'INFO'
                        & $reportStep 20 'Running diskpart' 'diskpart clean all (NVMe SSD)'

                        $diskpartOutput = & diskpart /s $diskpartFile 2>&1
                        $diskpartExitCode = $LASTEXITCODE

                        Remove-Item $diskpartFile -Force -ErrorAction SilentlyContinue

                        if ($diskpartExitCode -eq 0 -and ($diskpartOutput -join "`n") -match 'succeeded') {
                            $ssdEraseSuccess = $true
                            # 'clean all' zero-fills every sector, so the media is left at 0x00.
                            $finalPattern = [byte]0x00
                            Write-OperationLog -Message "diskpart clean all completed successfully for NVMe SSD disk $DiskNumber" -LogLevel 'SUCCESS'
                        }
                        else {
                            $diskpartText = ($diskpartOutput -join "`n").Trim()
                            Write-OperationLog -Message "diskpart clean all did not confirm success for NVMe disk (exit: $diskpartExitCode): $diskpartText" -LogLevel 'WARNING'
                        }
                    }
                    catch {
                        Write-OperationLog -Message "diskpart failed for NVMe SSD disk ${DiskNumber}: $($_.Exception.Message)" -LogLevel 'WARNING'
                        if (Test-Path $diskpartFile) {
                            Remove-Item $diskpartFile -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
                else {
                    # ── Other SSD protocol (SAS, USB, Unknown) ───────────
                    & $reportStep 10 'Erasing SSD' "diskpart clean all ($protocol)"
                    Write-OperationLog -Message "Performing $protocol SSD secure erase on disk $DiskNumber via diskpart clean all" -LogLevel 'INFO'

                    & $assertDiskIdentity
                    try {
                        $diskpartFile = Join-Path $env:TEMP "erase_disk_$DiskNumber.txt"
                        @(
                            "select disk $DiskNumber"
                            'clean all'
                        ) | Set-Content -Path $diskpartFile -Encoding ASCII -Force

                        $diskpartOutput = & diskpart /s $diskpartFile 2>&1
                        $diskpartExitCode = $LASTEXITCODE

                        Remove-Item $diskpartFile -Force -ErrorAction SilentlyContinue

                        if ($diskpartExitCode -eq 0 -and ($diskpartOutput -join "`n") -match 'succeeded') {
                            $ssdEraseSuccess = $true
                            # 'clean all' zero-fills every sector, so the media is left at 0x00.
                            $finalPattern = [byte]0x00
                            Write-OperationLog -Message "diskpart clean all completed for $protocol SSD disk $DiskNumber" -LogLevel 'SUCCESS'
                        }
                        else {
                            $diskpartText = ($diskpartOutput -join "`n").Trim()
                            Write-OperationLog -Message "diskpart clean all did not confirm success for $protocol SSD (exit: $diskpartExitCode): $diskpartText" -LogLevel 'WARNING'
                        }
                    }
                    catch {
                        Write-OperationLog -Message "diskpart failed for $protocol SSD disk ${DiskNumber}: $($_.Exception.Message)" -LogLevel 'WARNING'
                        if (Test-Path $diskpartFile) {
                            Remove-Item $diskpartFile -Force -ErrorAction SilentlyContinue
                        }
                    }
                }

                # ── SSD Fallback if diskpart failed ──────────────────────
                if (-not $ssdEraseSuccess) {
                    Write-OperationLog -Message "WARNING: SSD-specific secure erase failed for disk $DiskNumber. Falling back to Clear-Disk + overwrite. SSD overwrite is unreliable due to wear-leveling and over-provisioning - hardware-level erase is recommended." -LogLevel 'WARNING'

                    # Timeout check before fallback Clear-Disk
                    if (& $checkTimeout) {
                        return (& $handleTimeoutAbort $diskDescription "Secure (SSD fallback, $protocol)" $diskSerial $diskModel $diskSizeGB)
                    }

                    & $reportStep 30 'Fallback: Clear-Disk' 'SSD diskpart failed - falling back to Clear-Disk + overwrite'

                    & $assertDiskIdentity
                    Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
                    Write-OperationLog -Message "Fallback Clear-Disk completed for SSD disk $DiskNumber" -LogLevel 'INFO'

                    # Timeout check before fallback Invoke-SecureOverwrite
                    if (& $checkTimeout) {
                        return (& $handleTimeoutAbort $diskDescription "Secure (SSD fallback, $protocol)" $diskSerial $diskModel $diskSizeGB)
                    }

                    & $reportStep 40 'Fallback: Overwriting' 'Overwriting SSD (unreliable for wear-leveled media)'
                    $targetPath = "\\.\PhysicalDrive$DiskNumber"

                    & $assertDiskIdentity
                    $overwriteResult = Invoke-SecureOverwrite -TargetPath $targetPath -Passes 1 -ReportProgress {
                        param($info)
                        & $reportStep ([int](40 + ($info.PercentComplete * 0.25))) 'Fallback overwrite' "Pass $($info.Pass) of $($info.TotalPasses)"
                    }

                    if ($overwriteResult.Success) {
                        $finalPattern = $overwriteResult.FinalPattern
                        Write-OperationLog -Message "Fallback SSD overwrite completed: $($overwriteResult.BytesOverwritten) bytes, $($overwriteResult.Duration)" -LogLevel 'WARNING'
                    }
                    else {
                        Write-OperationLog -Message "Fallback SSD overwrite issue: $($overwriteResult.Message)" -LogLevel 'ERROR'
                        throw "Fallback SSD overwrite failed: $($overwriteResult.Message)"
                    }
                }

                & $reportStep 70 'Erase complete' "Secure SSD erase finished ($protocol)"
            }
        }

        # ── 5. Verification (unless -SkipVerification) ──────────────────
        $verificationResult = $null

        if (-not $SkipVerification) {

            # Timeout check before Test-EraseVerification
            if (& $checkTimeout) {
                return (& $handleTimeoutAbort $diskDescription $EraseMethod $diskSerial $diskModel $diskSizeGB)
            }

            # `$null -eq` and not `-not $finalPattern`: a legitimate pattern of
            # 0x00 is the commonest outcome and is falsy, so a truthiness test here
            # would skip verification on exactly the runs that most need it.
            if ($null -eq $finalPattern) {
                $verificationSkipReason = if ($EraseMethod -eq 'Quick') {
                    'Verification skipped: Quick writes nothing to the media, so there is no pattern to verify and nothing was sanitized.'
                }
                else {
                    'Verification skipped: the erase did not leave a predictable pattern on the media (an incomplete pass, or a random final pass), so sampling cannot confirm it.'
                }
                Write-OperationLog -Message $verificationSkipReason -LogLevel 'WARNING'
                & $reportStep 85 'Verification skipped' $verificationSkipReason
            }
            else {

                & $reportStep 75 'Verifying erasure' 'Post-erase sector sampling'
                Write-OperationLog -Message "Starting post-erase verification for disk $DiskNumber against expected byte 0x$($finalPattern.ToString('X2'))" -LogLevel 'INFO'

                try {
                    # The expected pattern is not a constant here. It is the byte the
                    # erase actually wrote, carried through from the method that wrote
                    # it. Hardcoding 0x00 at this call site while a method wrote
                    # something else is the defect this parameter exists to prevent.
                    $verificationResult = Test-EraseVerification -DiskNumber $DiskNumber -ExpectedPattern $finalPattern

                    if ($verificationResult.Verified) {
                        $verified = $true
                        Write-OperationLog -Message "Verification PASSED: $($verificationResult.SamplesPassed)/$($verificationResult.SamplesChecked) samples clean ($($verificationResult.Duration))" -LogLevel 'SUCCESS'
                    }
                    else {
                        Write-OperationLog -Message "Verification FAILED: $($verificationResult.SamplesFailed)/$($verificationResult.SamplesChecked) samples still contain data. $($verificationResult.Message)" -LogLevel 'WARNING'
                    }
                }
                catch {
                    Write-OperationLog -Message "Verification error: $($_.Exception.Message)" -LogLevel 'WARNING'
                }

                & $reportStep 85 'Verification complete' $(if ($verified) { 'Erase verified' } else { 'Verification did not pass' })

            }
        }
        else {
            Write-OperationLog -Message 'Post-erase verification skipped by user request.' -LogLevel 'INFO'
        }

        # ── 5b. Optional reformat, only after a verified erase ──────────
        #
        # A finished erase leaves the disk RAW. That is correct for a destruction
        # tool, but an operator who does not know that reads a disk with no drive
        # letter as a broken disk. -Reformat brings it back, and is gated so that a
        # filesystem is never written over a disk we have not confirmed to be clean:
        # doing so would bury any residual data under a fresh directory structure
        # and make it harder for a later audit to find.
        if ($Reformat) {
            & $reportStep 87 'Reformatting' 'Creating a new partition and filesystem'

            if ($SkipVerification) {
                $reformatMessage = 'Reformat skipped: -SkipVerification was specified, so the erase was never verified. EraseDrive does not write a filesystem onto a disk it has not confirmed to be clean.'
                Write-OperationLog -Message $reformatMessage -LogLevel 'WARNING'
            }
            elseif (-not $verified) {
                $reformatMessage = 'Reformat skipped: post-erase verification did not pass, so residual data may remain. Writing a filesystem now would make that data harder to detect.'
                Write-OperationLog -Message $reformatMessage -LogLevel 'WARNING'
            }
            elseif (& $checkTimeout) {
                $reformatMessage = "Reformat skipped: the operation reached its $TimeoutMinutes minute timeout after the erase finished. The erase and its verification are unaffected."
                Write-OperationLog -Message $reformatMessage -LogLevel 'WARNING'
            }
            elseif ($ReformatFileSystem -eq 'FAT32' -and $diskSizeGB -gt 32) {
                $reformatMessage = "Reformat skipped: FAT32 cannot address this ${diskSizeGB} GB disk (Windows caps FAT32 volumes at 32 GB). Re-run with -ReformatFileSystem exFAT or NTFS."
                Write-OperationLog -Message $reformatMessage -LogLevel 'WARNING'
            }
            elseif ($ReformatPartitionStyle -eq 'MBR' -and $diskSizeGB -gt 2048) {
                $reformatMessage = "Reformat skipped: MBR cannot address this ${diskSizeGB} GB disk (MBR is limited to 2 TB). Re-run with -ReformatPartitionStyle GPT."
                Write-OperationLog -Message $reformatMessage -LogLevel 'WARNING'
            }
            elseif ($ReformatFileSystem -ne 'NTFS' -and $ReformatLabel.Length -gt 11) {
                $reformatMessage = "Reformat skipped: the label '$ReformatLabel' is $($ReformatLabel.Length) characters, and $ReformatFileSystem volumes allow at most 11."
                Write-OperationLog -Message $reformatMessage -LogLevel 'WARNING'
            }
            else {
                try {
                    # The disk identity was pinned before the erase. Re-check it before
                    # writing anything back, exactly as every destructive step does: a
                    # hot-plug between erase and reformat would format a different disk.
                    & $assertDiskIdentity

                    # Do NOT trust the partition layout Windows reports here, and do
                    # NOT skip initialization because it claims to already have one.
                    #
                    # The erase just wrote zeros over every sector, sector 0 included.
                    # Windows then derives a layout from that all-zero boot sector and
                    # reports nonsense: measured on a 114.6 GB stick it came back as
                    # PartitionStyle MBR with a FAT16 partition of the full disk size
                    # at offset 0, and LargestFreeExtent of 0. An earlier version of
                    # this code saw "MBR", concluded the disk was already initialized,
                    # skipped Initialize-Disk, and New-Partition then failed with
                    # "Not enough available capacity" because by that phantom layout
                    # there was no free space left.
                    #
                    # So normalize unconditionally: refresh the cached layout, clear
                    # whatever table is claimed to be there, then initialize. Clearing
                    # is safe and cheap at this point: the media is already zeroed and
                    # verification has already passed.
                    try { Update-HostStorageCache -ErrorAction Stop }
                    catch { Write-OperationLog -Message "Could not refresh the storage cache before reformat: $($_.Exception.Message)" -LogLevel 'WARNING' }

                    $reportedStyle = "$((Get-Disk -Number $DiskNumber -ErrorAction Stop).PartitionStyle)"
                    Write-OperationLog -Message "Disk $DiskNumber reports PartitionStyle '$reportedStyle' after the overwrite; normalizing before partitioning." -LogLevel 'INFO'

                    if ($reportedStyle -ne 'RAW' -and -not [string]::IsNullOrWhiteSpace($reportedStyle)) {
                        & $assertDiskIdentity
                        # Drop the phantom table. Tolerate failure: on a genuinely raw
                        # disk Clear-Disk has nothing to do and may object, which is
                        # not an error for our purposes.
                        try {
                            Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
                            Write-OperationLog -Message "Cleared the stale partition table on disk $DiskNumber" -LogLevel 'INFO'
                        }
                        catch {
                            Write-OperationLog -Message "Clear-Disk before reformat reported: $($_.Exception.Message). Continuing; the disk may already be raw." -LogLevel 'INFO'
                        }
                    }

                    & $assertDiskIdentity
                    Write-OperationLog -Message "Initializing disk $DiskNumber as $ReformatPartitionStyle" -LogLevel 'INFO'
                    Initialize-Disk -Number $DiskNumber -PartitionStyle $ReformatPartitionStyle -Confirm:$false -ErrorAction Stop

                    # Confirm there is actually room before asking for the maximum size,
                    # so a failure names the real reason instead of surfacing a bare
                    # "Not enough available capacity".
                    $postInit = Get-Disk -Number $DiskNumber -ErrorAction Stop
                    if ($postInit.LargestFreeExtent -le 0) {
                        throw "after initializing as $ReformatPartitionStyle the disk still reports no free extent (allocated $($postInit.AllocatedSize) of $($postInit.Size) bytes), so no partition can be created."
                    }

                    & $assertDiskIdentity
                    Write-OperationLog -Message "Creating a full-size partition on disk $DiskNumber" -LogLevel 'INFO'
                    $newPartition = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -AssignDriveLetter -ErrorAction Stop

                    # New-Partition returns the drive letter as a char, and it can come
                    # back unset if Windows has not settled yet, so re-read it. Format by
                    # letter rather than by partition object: -DriveLetter takes a char,
                    # where -Partition takes a live CimInstance that nothing but the real
                    # Storage stack can produce.
                    $reformatDriveLetter = "$($newPartition.DriveLetter)".Trim([char]0, ' ')
                    if ([string]::IsNullOrWhiteSpace($reformatDriveLetter)) {
                        $settled = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue |
                            Where-Object { $_.DriveLetter } |
                            Select-Object -First 1
                        if ($settled) { $reformatDriveLetter = "$($settled.DriveLetter)".Trim([char]0, ' ') }
                    }

                    if ([string]::IsNullOrWhiteSpace($reformatDriveLetter)) {
                        throw 'the new partition was created but Windows assigned it no drive letter, so it could not be formatted. Assign a letter to it in Disk Management and format it there.'
                    }

                    & $assertDiskIdentity
                    & $reportStep 88 'Reformatting' "Formatting drive ${reformatDriveLetter}: as $ReformatFileSystem"
                    $null = Format-Volume -DriveLetter $reformatDriveLetter -FileSystem $ReformatFileSystem -NewFileSystemLabel $ReformatLabel -Confirm:$false -Force -ErrorAction Stop

                    $reformatted = $true
                    $reformatMessage = "Disk reformatted as $ReformatFileSystem ($ReformatPartitionStyle), label '$ReformatLabel', mounted as drive ${reformatDriveLetter}:."
                    Write-OperationLog -Message $reformatMessage -LogLevel 'SUCCESS'
                }
                catch {
                    # The erase succeeded and was verified. A reformat failure is a
                    # degraded outcome, not a failed erase, so it must not flip Success.
                    # Clear the drive letter: reporting one alongside Reformatted=$false
                    # would suggest a usable volume that does not exist.
                    $reformatDriveLetter = $null
                    $reformatMessage = "Reformat failed after a successful, verified erase: $($_.Exception.Message) The data is destroyed and the certificate is valid; the disk itself is unharmed."
                    Write-OperationLog -Message $reformatMessage -LogLevel 'WARNING'
                }
            }
        }

        # ── 6. Generate erasure certificate ──────────────────────────────
        & $reportStep 90 'Generating certificate' 'Erasure certificate'

        try {
            $methodDescription = switch ($EraseMethod) {
                'Quick'    { 'Quick (Clear-Disk only, NO overwrite, NOT a sanitization method)' }
                'Standard' { 'Standard (Clear-Disk + single-pass zero overwrite)' }
                'Secure' {
                    if ($mediaType -eq 'SSD' -and $protocol -eq 'NVMe') { 'Secure (NVMe diskpart clean all)' }
                    elseif ($mediaType -eq 'SSD' -and $protocol -eq 'SATA') { 'Secure (SATA diskpart clean all)' }
                    elseif ($mediaType -eq 'SSD') { "Secure (SSD diskpart clean all, $protocol)" }
                    else { 'Secure (Clear-Disk + 3-pass overwrite)' }
                }
            }

            if ($reformatted) {
                # The certificate attests to what was destroyed. The verification result
                # it carries was captured before the reformat, so it stays truthful, but
                # an auditor who finds a live filesystem on a "destroyed" disk needs to
                # see that EraseDrive put it there, and when.
                $methodDescription = "$methodDescription; reformatted as $ReformatFileSystem after verification"
            }

            $certResult = New-ErasureCertificate `
                -OperationType 'DiskErase' `
                -TargetDescription $diskDescription `
                -Method $methodDescription `
                -DiskSerial $diskSerial `
                -DiskModel $diskModel `
                -DiskSizeGB $diskSizeGB `
                -VerificationResult $verificationResult `
                -OperatorName ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

            if ($certResult.Success) {
                $certificatePath = $certResult.FilePath
                $pdfCertificatePath = $certResult.PdfFilePath
                $licenseTier = $certResult.LicenseTier
                Write-OperationLog -Message "Erasure certificate generated: $certificatePath (ID: $($certResult.CertificateId))" -LogLevel 'SUCCESS'
                Write-AuditLog -EventType 'CertificateGenerated' -Message "Certificate ID: $($certResult.CertificateId), Path: $certificatePath, PDF: $pdfCertificatePath, Tier: $licenseTier" -TargetDescription "Disk $DiskNumber"
            }
            else {
                Write-OperationLog -Message 'Failed to generate erasure certificate.' -LogLevel 'WARNING'
            }
        }
        catch {
            Write-OperationLog -Message "Certificate generation failed: $($_.Exception.Message)" -LogLevel 'WARNING'
        }

        # ── Done ─────────────────────────────────────────────────────────
        $stopwatch.Stop()
        & $reportStep 100 'Complete' 'Disk erase finished'

        $message = "Disk $DiskNumber ($diskModel, $diskSizeGB GB) erased successfully using $EraseMethod method ($mediaType/$protocol). Verified: $verified."
        if ($EraseMethod -eq 'Quick') {
            $message = "$message WARNING: Quick removed the partition table only. No data was overwritten and the contents remain recoverable. This is not a sanitization and carries no compliance claim."
        }
        if ($reformatMessage) {
            $message = "$message $reformatMessage"
        }
        elseif (-not $Reformat) {
            $message = "$message The disk was left raw (no partitions, no drive letter), which is the normal result of an erase."
        }
        Write-OperationLog -Message $message -LogLevel 'SUCCESS'
        Write-AuditLog -EventType 'OperationCompleted' -Message $message -TargetDescription "Disk $DiskNumber"

        [PSCustomObject]@{
            Success            = $true
            Message            = $message
            DiskNumber         = $DiskNumber
            Method             = $EraseMethod
            Verified           = $verified
            CertificatePath    = $certificatePath
            PdfCertificatePath = $pdfCertificatePath
            LicenseTier        = $licenseTier
            Reformatted        = $reformatted
            ReformatMessage    = $reformatMessage
            DriveLetter        = $reformatDriveLetter
            Duration           = $stopwatch.Elapsed
        }
    }
    catch {
        $stopwatch.Stop()
        $errorMessage = "Disk erase failed for disk ${DiskNumber}: $($_.Exception.Message)"
        Write-OperationLog -Message $errorMessage -LogLevel 'ERROR'
        Write-AuditLog -EventType 'OperationFailed' -Message $errorMessage -TargetDescription "Disk $DiskNumber"

        [PSCustomObject]@{
            Success            = $false
            Message            = $errorMessage
            DiskNumber         = $DiskNumber
            Method             = $EraseMethod
            Verified           = $false
            CertificatePath    = $null
            PdfCertificatePath = $null
            LicenseTier        = $licenseTier
            Reformatted        = $reformatted
            ReformatMessage    = $reformatMessage
            DriveLetter        = $reformatDriveLetter
            Duration           = $stopwatch.Elapsed
        }
    }
    finally {
        if ($operationLock -and $operationLock.Acquired) {
            Exit-OperationLock -Mutex $operationLock.Mutex
        }
    }
}

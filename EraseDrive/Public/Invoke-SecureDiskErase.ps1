function Invoke-SecureDiskErase {
    <#
    .SYNOPSIS
        Performs complete disk erasure with SSD-aware handling.

    .DESCRIPTION
        Erases the specified disk using the appropriate method for its media type and bus
        protocol. The function first validates the disk is safe to erase (not a system or
        boot disk), then queries hardware characteristics to select the optimal erasure
        strategy.

        Standard method uses Clear-Disk to remove all partition, volume, and OEM data.

        Secure method applies media-appropriate deep erasure:
        - HDD: Clear-Disk followed by a 3-pass overwrite of the raw physical device
        - SSD (SATA): diskpart 'clean all' via a temporary script file
        - SSD (NVMe): diskpart 'clean all' with NVMe-specific handling logged
        - Fallback: If SSD-specific commands fail, warns that SSD overwrite is unreliable
          due to wear-leveling and over-provisioning, then performs Clear-Disk + overwrite

        Post-erase verification samples sectors to confirm data was destroyed (unless
        -SkipVerification is specified). An erasure certificate is generated upon completion.

    .PARAMETER DiskNumber
        The disk number to erase (as shown by Get-Disk or Disk Management).

    .PARAMETER EraseMethod
        'Standard' performs a fast partition/volume removal. 'Secure' performs media-aware
        deep erasure. Default: Standard

    .PARAMETER SkipVerification
        When specified, skips the post-erase sector verification step. Not recommended
        for compliance-sensitive erasures.

    .PARAMETER ReportProgress
        Optional scriptblock callback invoked with progress updates. Receives a hashtable
        with keys: PercentComplete (int), Status (string), CurrentOperation (string).

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
        [ValidateSet('Standard', 'Secure')]
        [string]$EraseMethod = 'Standard',

        [Parameter()]
        [switch]$SkipVerification,

        [Parameter()]
        [scriptblock]$ReportProgress,

        [Parameter()]
        [int]$TimeoutMinutes = 0
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $verified = $false
    $certificatePath = $null
    $pdfCertificatePath = $null
    $licenseTier = 'Free'
    $operationLock = $null

    # Helper to invoke progress callback safely
    $reportStep = {
        param([int]$Percent, [string]$Status, [string]$Operation)
        if ($ReportProgress) {
            try {
                & $ReportProgress @{
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
                Duration           = $stopwatch.Elapsed
            }
        }

        # ── 4. Perform erasure ───────────────────────────────────────────
        if ($EraseMethod -eq 'Standard') {
            # ── Standard: Clear-Disk only ────────────────────────────────

            # Timeout check before Clear-Disk
            if (& $checkTimeout) {
                return (& $handleTimeoutAbort $diskDescription 'Standard (Clear-Disk)' $diskSerial $diskModel $diskSizeGB)
            }

            & $reportStep 10 'Erasing disk' 'Clear-Disk (Standard)'
            Write-OperationLog -Message "Executing Clear-Disk for disk $DiskNumber (Standard)" -LogLevel 'INFO'

            & $assertDiskIdentity
            Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
            Write-OperationLog -Message "Clear-Disk completed for disk $DiskNumber" -LogLevel 'SUCCESS'

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

            & $reportStep 75 'Verifying erasure' 'Post-erase sector sampling'
            Write-OperationLog -Message "Starting post-erase verification for disk $DiskNumber" -LogLevel 'INFO'

            try {
                $verificationResult = Test-EraseVerification -DiskNumber $DiskNumber

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
        else {
            Write-OperationLog -Message 'Post-erase verification skipped by user request.' -LogLevel 'INFO'
        }

        # ── 6. Generate erasure certificate ──────────────────────────────
        & $reportStep 90 'Generating certificate' 'Erasure certificate'

        try {
            $methodDescription = switch ($EraseMethod) {
                'Standard' { 'Standard (Clear-Disk)' }
                'Secure' {
                    if ($mediaType -eq 'SSD' -and $protocol -eq 'NVMe') { 'Secure (NVMe diskpart clean all)' }
                    elseif ($mediaType -eq 'SSD' -and $protocol -eq 'SATA') { 'Secure (SATA diskpart clean all)' }
                    elseif ($mediaType -eq 'SSD') { "Secure (SSD diskpart clean all, $protocol)" }
                    else { 'Secure (Clear-Disk + 3-pass overwrite)' }
                }
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
            Duration           = $stopwatch.Elapsed
        }
    }
    finally {
        if ($operationLock -and $operationLock.Acquired) {
            Exit-OperationLock -Mutex $operationLock.Mutex
        }
    }
}

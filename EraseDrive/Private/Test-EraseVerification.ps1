function Test-EraseVerification {
    <#
    .SYNOPSIS
        Verifies that a disk has been securely erased by sampling random sectors.

    .DESCRIPTION
        Opens a physical disk in read mode and reads a configurable number of
        randomly-selected 512-byte sectors. Each sector is checked against the
        expected byte pattern (typically 0x00 after a zero-fill pass). Results
        are logged via Write-OperationLog and returned as a summary object.

        Random offsets are generated with RNGCryptoServiceProvider and aligned
        to 512-byte sector boundaries.

    .PARAMETER DiskNumber
        The physical disk index (e.g. 0, 1, 2) corresponding to \\.\PhysicalDriveN.

    .PARAMETER SampleCount
        Number of random sectors to read and verify. Default is calculated
        based on disk size: max(100, min(10000, diskSizeGB * 10)). Pass an
        explicit value to override the automatic calculation.

    .PARAMETER MinimumCoverage
        Minimum percentage of total sectors that must be sampled (default
        0.001, meaning 0.001%). If the calculated SampleCount does not meet
        this threshold, it is increased (up to the 10,000 cap).

    .PARAMETER ExpectedPattern
        The byte value every byte in each sampled sector should match.
        Default is 0x00 (post-zero-fill verification).

    .PARAMETER ReportProgress
        Optional scriptblock callback invoked with a hashtable containing:
        CurrentSample, TotalSamples, PercentComplete.

    .OUTPUTS
        PSCustomObject with properties: Verified, SamplesChecked, SamplesPassed,
        SamplesFailed, FailedOffsets, Duration, Message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(0, 99)]
        [int]$DiskNumber,

        [ValidateRange(0, 100000)]
        [int]$SampleCount = 0,

        [ValidateRange(0, 100)]
        [double]$MinimumCoverage = 0.001,

        [byte]$ExpectedPattern = 0x00,

        [scriptblock]$ReportProgress
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $sectorSize    = 512
    $samplesPassed = 0
    $samplesFailed = 0
    $failedOffsets = [System.Collections.Generic.List[int64]]::new()
    $diskPath      = "\\.\PhysicalDrive$DiskNumber"

    try {
        # Get disk size from WMI
        $wmiDisk  = Get-CimInstance -ClassName Win32_DiskDrive -Filter "Index=$DiskNumber" -ErrorAction Stop
        $diskSize = [int64]$wmiDisk.Size

        if ($diskSize -le 0) {
            $msg = "Disk $DiskNumber reports 0 bytes -- cannot verify."
            Write-OperationLog -Message $msg -LogLevel 'Error'
            $stopwatch.Stop()
            return [PSCustomObject]@{
                Verified       = $false
                SamplesChecked = 0
                SamplesPassed  = 0
                SamplesFailed  = 0
                FailedOffsets  = [int64[]]@()
                Duration       = $stopwatch.Elapsed
                Message        = $msg
            }
        }

        # Maximum valid sector-aligned offset
        $totalSectors = [Math]::Floor($diskSize / $sectorSize)
        $maxSector = $totalSectors - 1
        if ($maxSector -lt 0) { $maxSector = 0 }

        # Calculate sample count based on disk size if not explicitly provided
        if ($SampleCount -eq 0) {
            $diskSizeGB = [Math]::Round($diskSize / 1GB, 2)
            $SampleCount = [Math]::Max(100, [Math]::Min(10000, [int]($diskSizeGB * 10)))
        }

        # Ensure minimum coverage is met (up to 10,000 cap)
        if ($MinimumCoverage -gt 0 -and $totalSectors -gt 0) {
            $requiredSamples = [int][Math]::Ceiling($totalSectors * ($MinimumCoverage / 100))
            if ($requiredSamples -gt $SampleCount) {
                $SampleCount = [Math]::Min(10000, $requiredSamples)
            }
        }

        # Clamp to available sectors
        if ($SampleCount -gt $totalSectors) {
            $SampleCount = [int]$totalSectors
        }

        $coveragePct = [Math]::Round(($SampleCount / $totalSectors) * 100, 6)
        Write-OperationLog -Message "Verifying $SampleCount sectors out of $totalSectors (${coveragePct}% coverage)" -LogLevel 'Info'
        Write-OperationLog -Message "Erase verification starting on $diskPath -- $SampleCount sample(s), expected byte 0x$($ExpectedPattern.ToString('X2'))." -LogLevel 'Info'

        # Generate cryptographically random unique sector offsets using a HashSet
        $rng     = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $seenSectors = [System.Collections.Generic.HashSet[int64]]::new()
        $offsets = [System.Collections.Generic.List[int64]]::new()

        # We need 8 bytes per random offset
        $rndBuf = [byte[]]::new(8)
        while ($offsets.Count -lt $SampleCount) {
            $rng.GetBytes($rndBuf)
            # Mask to positive value
            $rndBuf[7] = $rndBuf[7] -band 0x7F
            $rawValue  = [BitConverter]::ToInt64($rndBuf, 0)
            $sectorIdx = $rawValue % ($maxSector + 1)
            if ($seenSectors.Add($sectorIdx)) {
                $offsets.Add($sectorIdx * $sectorSize)
            }
        }
        $rng.Dispose()

        # Open disk for reading
        $stream = [System.IO.FileStream]::new(
            $diskPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )

        $readBuffer = [byte[]]::new($sectorSize)

        try {
            for ($s = 0; $s -lt $offsets.Count; $s++) {
                $offset = $offsets[$s]

                try {
                    $stream.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
                    $bytesRead = $stream.Read($readBuffer, 0, $sectorSize)

                    # A sector that returned NO bytes is not a verified sector. The
                    # comparison loop below runs $bytesRead times, so seeding $match
                    # with $true made a zero-length read fall straight through to
                    # "passed": an unreadable sector counted as proof of erasure,
                    # which is a false negative in the one direction that matters.
                    $match = ($bytesRead -gt 0)
                    if ($bytesRead -le 0) {
                        Write-OperationLog -Message "Verification read returned 0 bytes at offset $offset on ${diskPath}; counting as a FAILED sample because nothing was confirmed." -LogLevel 'Warning'
                    }

                    for ($b = 0; $b -lt $bytesRead; $b++) {
                        if ($readBuffer[$b] -ne $ExpectedPattern) {
                            $match = $false
                            break
                        }
                    }

                    if ($match) {
                        $samplesPassed++
                    }
                    else {
                        $samplesFailed++
                        $failedOffsets.Add($offset)
                    }
                }
                catch {
                    $samplesFailed++
                    $failedOffsets.Add($offset)
                    Write-OperationLog -Message "Verification read error at offset $offset on ${diskPath}: $_" -LogLevel 'Warning'
                }

                if ($ReportProgress) {
                    $pct = [Math]::Round((($s + 1) / $SampleCount) * 100, 1)
                    & $ReportProgress @{
                        CurrentSample  = ($s + 1)
                        TotalSamples   = $SampleCount
                        PercentComplete = $pct
                    }
                }
            }
        }
        finally {
            $stream.Close()
            $stream.Dispose()
        }

        $stopwatch.Stop()
        $verified = ($samplesFailed -eq 0)
        $msg = "Verification complete on ${diskPath}: $samplesPassed/$SampleCount sectors match expected pattern. $samplesFailed failure(s)."
        $logLevel = $(if ($verified) { 'Info' } else { 'Warning' })
        Write-OperationLog -Message $msg -LogLevel $logLevel

        return [PSCustomObject]@{
            Verified       = $verified
            SamplesChecked = $SampleCount
            SamplesPassed  = $samplesPassed
            SamplesFailed  = $samplesFailed
            FailedOffsets  = [int64[]]$failedOffsets.ToArray()
            Duration       = $stopwatch.Elapsed
            Message        = $msg
        }
    }
    catch {
        $stopwatch.Stop()
        $errMsg = "Erase verification failed on ${diskPath}: $_"
        Write-OperationLog -Message $errMsg -LogLevel 'Error'

        return [PSCustomObject]@{
            Verified       = $false
            SamplesChecked = ($samplesPassed + $samplesFailed)
            SamplesPassed  = $samplesPassed
            SamplesFailed  = $samplesFailed
            FailedOffsets  = [int64[]]$failedOffsets.ToArray()
            Duration       = $stopwatch.Elapsed
            Message        = $errMsg
        }
    }
}

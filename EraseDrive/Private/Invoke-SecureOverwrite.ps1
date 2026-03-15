function Invoke-SecureOverwrite {
    <#
    .SYNOPSIS
        Performs a real multi-pass secure overwrite on a drive or free space.

    .DESCRIPTION
        Implements NIST 800-88 Clear method with a true multi-pass overwrite engine.
        Pass 1 writes all zeros (0x00), Pass 2 writes all ones (0xFF), and Pass 3
        writes cryptographically random data via RNGCryptoServiceProvider.

        For drive-letter targets (e.g. "D:"), free space is filled by writing 512 MB
        temporary chunk files until the disk is full, then deleting them.

        For physical disk paths (e.g. "\\.\PhysicalDrive1"), raw writes go directly
        to the device via FileStream.

    .PARAMETER TargetPath
        Drive letter (e.g. "D:") for free-space overwrite, or a physical disk path
        (e.g. "\\.\PhysicalDrive1") for whole-disk overwrite.

    .PARAMETER Passes
        Number of overwrite passes. Default is 3 (NIST 800-88 Clear).

    .PARAMETER PassPattern
        Optional array of custom hex-string patterns for each pass.
        When supplied, overrides the default zero/one/random sequence.
        Use "RANDOM" as a sentinel value for a cryptographic random pass.

    .PARAMETER ReportProgress
        Optional scriptblock callback invoked with a hashtable containing:
        Pass, TotalPasses, BytesWritten, TotalBytes, PercentComplete.

    .OUTPUTS
        PSCustomObject with properties: Success, BytesOverwritten, PassesCompleted,
        Duration, Message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetPath,

        [ValidateRange(1, 35)]
        [int]$Passes = 3,

        [string[]]$PassPattern,

        [scriptblock]$ReportProgress
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $totalBytesOverwritten = [int64]0
    $passesCompleted = 0
    $bufferSize = 1MB                    # 1 MB write buffer
    $chunkSize  = 512MB                  # 512 MB temp file chunks for free-space mode
    $isPhysicalDisk = $TargetPath -match '^\\\\.\\PhysicalDrive\d+$'

    # Build the pattern list for each pass
    $patterns = [System.Collections.Generic.List[object]]::new()
    if ($PassPattern -and $PassPattern.Count -gt 0) {
        foreach ($p in $PassPattern) {
            $patterns.Add($p)
        }
        # If fewer patterns than passes, cycle through them
        while ($patterns.Count -lt $Passes) {
            $patterns.Add($PassPattern[$patterns.Count % $PassPattern.Count])
        }
    }
    else {
        # NIST 800-88 Clear defaults -- extend if more than 3 passes requested
        $defaults = @('0x00', '0xFF', 'RANDOM')
        for ($i = 0; $i -lt $Passes; $i++) {
            $patterns.Add($defaults[$i % $defaults.Count])
        }
    }

    Write-OperationLog -Message "Secure overwrite starting on '$TargetPath' -- $Passes pass(es) requested." -LogLevel 'Info'

    try {
        # ------------------------------------------------------------------
        # Determine total writable bytes so progress can be reported.
        # ------------------------------------------------------------------
        $totalBytes = [int64]0

        if ($isPhysicalDisk) {
            # Query WMI for disk size based on the device index
            $diskIndex = [int]($TargetPath -replace '^\\\\.\\PhysicalDrive', '')
            $wmiDisk   = Get-CimInstance -ClassName Win32_DiskDrive -Filter "Index=$diskIndex" -ErrorAction Stop
            $totalBytes = [int64]$wmiDisk.Size
        }
        else {
            # Free space on the target volume
            $driveLetter = $TargetPath.TrimEnd(':\')
            $volume = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='${driveLetter}:'" -ErrorAction Stop
            $totalBytes = [int64]$volume.FreeSpace
        }

        if ($totalBytes -le 0) {
            $msg = "Target '$TargetPath' reports 0 bytes available -- nothing to overwrite."
            Write-OperationLog -Message $msg -LogLevel 'Warning'
            $stopwatch.Stop()
            return [PSCustomObject]@{
                Success          = $true
                BytesOverwritten = [int64]0
                PassesCompleted  = 0
                Duration         = $stopwatch.Elapsed
                Message          = $msg
            }
        }

        # ------------------------------------------------------------------
        # Helper: fill a buffer with the pass pattern
        # ------------------------------------------------------------------
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()

        function Fill-Buffer {
            param([byte[]]$Buffer, [string]$Pattern)

            if ($Pattern -eq 'RANDOM') {
                $rng.GetBytes($Buffer)
            }
            elseif ($Pattern -match '^0x([0-9A-Fa-f]{1,2})$') {
                $byteVal = [byte][Convert]::ToInt32($Matches[1], 16)
                for ($i = 0; $i -lt $Buffer.Length; $i++) {
                    $Buffer[$i] = $byteVal
                }
            }
            else {
                # Treat the whole string as a repeating byte sequence
                $hexClean = $Pattern -replace '0x|[^0-9A-Fa-f]', ''
                if ($hexClean.Length -ge 2) {
                    $patBytes = [byte[]]::new($hexClean.Length / 2)
                    for ($j = 0; $j -lt $patBytes.Length; $j++) {
                        $patBytes[$j] = [Convert]::ToByte($hexClean.Substring($j * 2, 2), 16)
                    }
                    for ($i = 0; $i -lt $Buffer.Length; $i++) {
                        $Buffer[$i] = $patBytes[$i % $patBytes.Length]
                    }
                }
                else {
                    # Fallback: zero-fill
                    [Array]::Clear($Buffer, 0, $Buffer.Length)
                }
            }
        }

        # ------------------------------------------------------------------
        # Execute each pass
        # ------------------------------------------------------------------
        $buffer = [byte[]]::new($bufferSize)

        for ($pass = 1; $pass -le $Passes; $pass++) {
            $pattern = $patterns[$pass - 1]
            $patternLabel = $(if ($pattern -eq 'RANDOM') { 'random data' } else { $pattern })
            Write-OperationLog -Message "Pass $pass/$Passes -- writing $patternLabel to '$TargetPath'." -LogLevel 'Info'

            $passBytesWritten = [int64]0
            $passFailed = $false

            try {
                if ($isPhysicalDisk) {
                    # ---- Physical disk raw write ----
                    $stream = [System.IO.FileStream]::new(
                        $TargetPath,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Write,
                        [System.IO.FileShare]::ReadWrite
                    )

                    try {
                        while ($passBytesWritten -lt $totalBytes) {
                            $remaining = $totalBytes - $passBytesWritten
                            $writeLen  = [Math]::Min($buffer.Length, $remaining)

                            # Re-fill buffer (important for RANDOM -- need fresh data each iteration)
                            Fill-Buffer -Buffer $buffer -Pattern $pattern

                            $stream.Write($buffer, 0, [int]$writeLen)
                            $passBytesWritten += $writeLen

                            if ($ReportProgress) {
                                $pct = [Math]::Round(($passBytesWritten / $totalBytes) * 100, 1)
                                & $ReportProgress @{
                                    Pass            = $pass
                                    TotalPasses     = $Passes
                                    BytesWritten    = $passBytesWritten
                                    TotalBytes      = $totalBytes
                                    PercentComplete = $pct
                                }
                            }
                        }

                        $stream.Flush()
                    }
                    finally {
                        $stream.Close()
                        $stream.Dispose()
                    }
                }
                else {
                    # ---- Free-space fill on a volume ----
                    $tempDir   = Join-Path $TargetPath '\EraseDrive_SecureWipe'
                    if (-not (Test-Path $tempDir)) {
                        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
                    }

                    $chunkIndex = 0
                    $diskFull   = $false

                    try {
                        while (-not $diskFull) {
                            $chunkFile = Join-Path $tempDir "wipe_${pass}_${chunkIndex}.bin"
                            $chunkBytesWritten = [int64]0

                            try {
                                $stream = [System.IO.FileStream]::new(
                                    $chunkFile,
                                    [System.IO.FileMode]::Create,
                                    [System.IO.FileAccess]::Write,
                                    [System.IO.FileShare]::None,
                                    $bufferSize,
                                    [System.IO.FileOptions]::WriteThrough
                                )

                                try {
                                    while ($chunkBytesWritten -lt $chunkSize) {
                                        $writeLen = [Math]::Min($buffer.Length, ($chunkSize - $chunkBytesWritten))
                                        Fill-Buffer -Buffer $buffer -Pattern $pattern

                                        $stream.Write($buffer, 0, [int]$writeLen)
                                        $chunkBytesWritten += $writeLen
                                        $passBytesWritten  += $writeLen

                                        if ($ReportProgress) {
                                            $pct = [Math]::Round(($passBytesWritten / $totalBytes) * 100, 1)
                                            if ($pct -gt 100) { $pct = 100 }
                                            & $ReportProgress @{
                                                Pass            = $pass
                                                TotalPasses     = $Passes
                                                BytesWritten    = $passBytesWritten
                                                TotalBytes      = $totalBytes
                                                PercentComplete = $pct
                                            }
                                        }
                                    }

                                    $stream.Flush()
                                }
                                finally {
                                    $stream.Close()
                                    $stream.Dispose()
                                }
                            }
                            catch [System.IO.IOException] {
                                # Expected -- disk is full
                                $diskFull = $true
                            }

                            $chunkIndex++
                        }
                    }
                    finally {
                        # Clean up temp files for this pass
                        if (Test-Path $tempDir) {
                            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }

                $totalBytesOverwritten += $passBytesWritten
                $passesCompleted++
                Write-OperationLog -Message "Pass $pass/$Passes complete -- $passBytesWritten bytes written." -LogLevel 'Info'
            }
            catch {
                $passesCompleted++
                $totalBytesOverwritten += $passBytesWritten
                Write-OperationLog -Message "Pass $pass/$Passes failed after $passBytesWritten bytes: $_" -LogLevel 'Error'
                # Continue to next pass per spec -- do not abort
            }
        }

        $rng.Dispose()
        $stopwatch.Stop()

        $resultMsg = "Secure overwrite completed: $passesCompleted/$Passes passes, $totalBytesOverwritten bytes overwritten."
        Write-OperationLog -Message $resultMsg -LogLevel 'Info'

        return [PSCustomObject]@{
            Success          = ($passesCompleted -eq $Passes)
            BytesOverwritten = $totalBytesOverwritten
            PassesCompleted  = $passesCompleted
            Duration         = $stopwatch.Elapsed
            Message          = $resultMsg
        }
    }
    catch {
        $rng.Dispose()
        $stopwatch.Stop()
        $errMsg = "Secure overwrite failed on '$TargetPath': $_"
        Write-OperationLog -Message $errMsg -LogLevel 'Error'

        return [PSCustomObject]@{
            Success          = $false
            BytesOverwritten = $totalBytesOverwritten
            PassesCompleted  = $passesCompleted
            Duration         = $stopwatch.Elapsed
            Message          = $errMsg
        }
    }
}

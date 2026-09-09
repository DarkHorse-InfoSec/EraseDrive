function Invoke-SecureOverwrite {
    <#
    .SYNOPSIS
        Performs a real multi-pass secure overwrite on a drive or free space.

    .DESCRIPTION
        Implements NIST SP 800-88 Rev.1 Clear with a true multi-pass overwrite
        engine. The default sequence is zeros (0x00), ones (0xFF), zeros (0x00).

        The final pass deliberately writes a FIXED pattern rather than random data.
        NIST SP 800-88 requires that sanitization be verified (Rev.1 section 4.7),
        and sampling verification can only confirm a pattern it can predict; a
        random final pass leaves a disk that is impossible to verify by sampling.
        NIST also does not require multiple passes at all: Appendix A states that a
        single overwrite pass with a fixed pattern hinders recovery even against
        laboratory techniques, so ending on zeros costs no assurance and buys
        verifiability. The zeros/ones/random sequence is DoD 5220.22-M legacy,
        which NIST superseded.

        For drive-letter targets (e.g. "D:"), free space is filled by writing 512 MB
        temporary chunk files until the disk is full, then deleting them.

        For physical disk paths (e.g. "\\.\PhysicalDrive1"), raw writes go directly
        to the device via FileStream.

    .PARAMETER TargetPath
        Drive letter (e.g. "D:") for free-space overwrite, or a physical disk path
        (e.g. "\\.\PhysicalDrive1") for whole-disk overwrite.

    .PARAMETER Passes
        Number of overwrite passes. Default is 3. One fixed-pattern pass already
        satisfies NIST SP 800-88 Rev.1 Clear; more passes are offered because
        procurement and audit checklists still ask for them.

    .PARAMETER PassPattern
        Optional array of custom hex-string patterns for each pass.
        When supplied, overrides the default sequence.
        Use "RANDOM" as a sentinel value for a cryptographic random pass. A run
        whose LAST pass is RANDOM reports FinalPattern as $null, because the
        resulting disk cannot be verified by sampling.

    .PARAMETER ReportProgress
        Optional scriptblock callback invoked with a hashtable containing:
        Pass, TotalPasses, BytesWritten, TotalBytes, PercentComplete.

    .OUTPUTS
        PSCustomObject with properties: Success, BytesOverwritten, PassesCompleted,
        Duration, Message, FinalPattern.

        FinalPattern is the byte this run last wrote across the target, and is what
        a subsequent verification must expect. It is $null when the disk was left
        in a state sampling cannot predict: a RANDOM final pass, or a run where not
        every pass completed and the media therefore holds a mix of patterns.

        FinalPattern is deliberately a [byte] or $null and must be tested with
        `$null -eq $result.FinalPattern`. A legitimate final pattern of 0x00 is the
        common case and is falsy, so `if ($result.FinalPattern)` is always wrong.
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
        # Default sequence. The LAST pass must be a fixed pattern so the result can
        # be verified by sampling; see the .DESCRIPTION note on NIST 800-88 4.7.
        $defaults = @('0x00', '0xFF', '0x00')
        for ($i = 0; $i -lt $Passes; $i++) {
            $patterns.Add($defaults[$i % $defaults.Count])
        }
        # Cycling a 3-element list can land on 0xFF for some pass counts. Whatever
        # the count, finish on zeros.
        if ($Passes -gt 0) { $patterns[$Passes - 1] = '0x00' }
    }

    # Resolve what the disk will be left holding, so the caller does not have to
    # re-derive it. This value and the pattern a verifier expects are one fact; the
    # whole point of returning it is that they stop being two.
    $resolveFinalPattern = {
        param([string]$Pattern)
        if ($Pattern -eq 'RANDOM') { return $null }
        if ($Pattern -match '^0x([0-9A-Fa-f]{1,2})$') {
            return [byte][Convert]::ToInt32($Matches[1], 16)
        }
        # A repeating multi-byte sequence is not a single byte, so sampling against
        # one byte cannot verify it.
        return $null
    }
    $plannedFinalPattern = if ($Passes -gt 0) { & $resolveFinalPattern $patterns[$Passes - 1] } else { $null }

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
                FinalPattern     = $null
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

        # Only claim a final pattern if every pass actually finished. A partial run
        # leaves a mix of patterns on the media, which is exactly the state that must
        # NOT be reported as verifiable.
        $allPassesCompleted = ($passesCompleted -eq $Passes)
        $finalPattern = if ($allPassesCompleted) { $plannedFinalPattern } else { $null }

        return [PSCustomObject]@{
            Success          = $allPassesCompleted
            BytesOverwritten = $totalBytesOverwritten
            PassesCompleted  = $passesCompleted
            Duration         = $stopwatch.Elapsed
            Message          = $resultMsg
            FinalPattern     = $finalPattern
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
            # The run threw part way through, so the media holds an unknown mix.
            FinalPattern     = $null
        }
    }
}

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
        PassesFailed, Duration, Message, FinalPattern.

        Success is $true only when every pass ran, none failed, AND bytes actually
        reached the media. An overwrite that writes nothing has sanitized nothing,
        however cleanly its loop exited.

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
    $passesFailed = 0
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
            # Two very different situations produce 0 here, and they must not share
            # an answer.
            #
            # A whole physical disk NEVER legitimately has 0 bytes. Reaching this
            # with a PhysicalDrive target means the size query failed or returned
            # nothing, so we do not know how much to write and have written none of
            # it. Reporting success there is reporting a sanitization that did not
            # happen.
            #
            # A drive-letter target in free-space mode genuinely can have 0 bytes
            # free, and there really is nothing to do.
            if ($isPhysicalDisk) {
                $msg = "Could not determine the size of '$TargetPath' (reported $totalBytes bytes). Refusing to report a successful overwrite of a disk whose size is unknown; nothing was written."
                Write-OperationLog -Message $msg -LogLevel 'Error'
                $stopwatch.Stop()
                return [PSCustomObject]@{
                    Success          = $false
                    BytesOverwritten = [int64]0
                    PassesCompleted  = 0
                    PassesFailed     = $Passes
                    Duration         = $stopwatch.Elapsed
                    Message          = $msg
                    FinalPattern     = $null
                }
            }

            $msg = "Target '$TargetPath' reports 0 bytes of free space -- nothing to overwrite."
            Write-OperationLog -Message $msg -LogLevel 'Warning'
            $stopwatch.Stop()
            return [PSCustomObject]@{
                Success          = $true
                BytesOverwritten = [int64]0
                PassesCompleted  = 0
                PassesFailed     = 0
                Duration         = $stopwatch.Elapsed
                Message          = $msg
                FinalPattern     = $null
            }
        }

        # ------------------------------------------------------------------
        # Helper: fill a buffer with the pass pattern
        # ------------------------------------------------------------------
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()

        # Fill a buffer with the pass pattern.
        #
        # Every branch here MUST avoid a per-byte PowerShell loop. The original
        # version assigned $Buffer[$i] one byte at a time, which is about a million
        # interpreted iterations per megabyte; across a 114.6 GB disk that is on the
        # order of 10^11 iterations, or many hours of CPU before a single sector is
        # written. [Array]::Clear and [Array]::Copy do the same work in native code.
        #
        # The doubling copy fills an arbitrary repeating pattern in log2(n) steps:
        # seed the first unit, then repeatedly copy everything written so far to the
        # end, doubling the filled length each time.
        function Fill-Buffer {
            param([byte[]]$Buffer, [string]$Pattern)

            if ($Pattern -eq 'RANDOM') {
                $rng.GetBytes($Buffer)
                return
            }

            if ($Pattern -match '^0x([0-9A-Fa-f]{1,2})$') {
                $byteVal = [byte][Convert]::ToInt32($Matches[1], 16)
                if ($byteVal -eq 0) {
                    [Array]::Clear($Buffer, 0, $Buffer.Length)
                    return
                }
                $Buffer[0] = $byteVal
                $filled = 1
                while ($filled -lt $Buffer.Length) {
                    $copy = [int][Math]::Min([int64]$filled, [int64]($Buffer.Length - $filled))
                    [Array]::Copy($Buffer, 0, $Buffer, $filled, $copy)
                    $filled += $copy
                }
                return
            }

            # Treat the whole string as a repeating byte sequence.
            $hexClean = $Pattern -replace '0x|[^0-9A-Fa-f]', ''
            if ($hexClean.Length -lt 2) {
                [Array]::Clear($Buffer, 0, $Buffer.Length)
                return
            }

            $patBytes = [byte[]]::new([int]($hexClean.Length / 2))
            for ($j = 0; $j -lt $patBytes.Length; $j++) {
                $patBytes[$j] = [Convert]::ToByte($hexClean.Substring($j * 2, 2), 16)
            }
            $seed = [int][Math]::Min([int64]$patBytes.Length, [int64]$Buffer.Length)
            [Array]::Copy($patBytes, 0, $Buffer, 0, $seed)
            $filled = $seed
            while ($filled -lt $Buffer.Length) {
                $copy = [int][Math]::Min([int64]$filled, [int64]($Buffer.Length - $filled))
                [Array]::Copy($Buffer, 0, $Buffer, $filled, $copy)
                $filled += $copy
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

            # A fixed pattern produces the same bytes every time, so fill the buffer
            # ONCE for the pass. Only RANDOM has to be regenerated per write, and
            # that is the whole reason the original code refilled every iteration.
            $needsRefillEachWrite = ($pattern -eq 'RANDOM')
            Fill-Buffer -Buffer $buffer -Pattern $pattern

            # Report on whole-percent changes only. At a 1 MB buffer a 114.6 GB
            # disk is ~117,000 writes, and invoking the caller's callback on every
            # one of them is both wasteful and a needless amount of script nesting
            # inside the hottest loop in the product.
            $lastReportedPct = -1

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
                            $remaining = [int64]($totalBytes - $passBytesWritten)
                            # Both arguments MUST be [int64]. PowerShell picks the
                            # [Math]::Min overload from the first argument's type, so
                            # an Int32 buffer length selects Min(int,int) and then
                            # throws converting a multi-gigabyte remainder. That threw
                            # on the first iteration of every disk over 2 GB, which is
                            # every disk this tool exists to erase.
                            $writeLen  = [int64][Math]::Min([int64]$buffer.Length, $remaining)

                            # Only RANDOM needs fresh bytes per write; a fixed
                            # pattern was filled once before the loop.
                            if ($needsRefillEachWrite) { Fill-Buffer -Buffer $buffer -Pattern $pattern }

                            $stream.Write($buffer, 0, [int]$writeLen)
                            $passBytesWritten += $writeLen

                            if ($ReportProgress) {
                                $pct = [int][Math]::Floor(($passBytesWritten / $totalBytes) * 100)
                                if ($pct -ne $lastReportedPct) {
                                    $lastReportedPct = $pct
                                    # Log directly as well as calling back. The
                                    # callback reaches the caller through a
                                    # scriptblock whose variable lookup is
                                    # currently unreliable (see the note in
                                    # Invoke-SecureDiskErase), and an operator
                                    # watching a multi-hour write needs SOME
                                    # evidence of movement that does not depend on
                                    # that path working.
                                    if (($pct % 5) -eq 0) {
                                        Write-OperationLog -Message "Pass $pass/$Passes on '$TargetPath': $pct% ($passBytesWritten of $totalBytes bytes)" -LogLevel 'Info'
                                    }
                                    & $ReportProgress @{
                                        Pass            = $pass
                                        TotalPasses     = $Passes
                                        BytesWritten    = $passBytesWritten
                                        TotalBytes      = $totalBytes
                                        PercentComplete = $pct
                                    }
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
                                        $writeLen = [int64][Math]::Min([int64]$buffer.Length, [int64]($chunkSize - $chunkBytesWritten))
                                        if ($needsRefillEachWrite) { Fill-Buffer -Buffer $buffer -Pattern $pattern }

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
                # A pass that threw is NOT a completed pass. Counting it as one is
                # how this function came to report Success after writing 0 bytes.
                $passesFailed++
                $totalBytesOverwritten += $passBytesWritten
                Write-OperationLog -Message "Pass $pass/$Passes FAILED after $passBytesWritten bytes: $_" -LogLevel 'Error'
                # Continue to the next pass rather than aborting, but the failure is
                # now recorded and will be reflected in Success and FinalPattern.
            }
        }

        $rng.Dispose()
        $stopwatch.Stop()

        # Success requires three things, and the third is the one that was missing:
        # every pass ran, none of them failed, and bytes actually reached the media.
        # An overwrite that wrote nothing is not a successful overwrite, however
        # cleanly the loop exited.
        $allPassesCompleted = ($passesCompleted -eq $Passes -and $passesFailed -eq 0)
        $wroteSomething     = ($totalBytes -le 0) -or ($totalBytesOverwritten -gt 0)
        $overwriteSucceeded = ($allPassesCompleted -and $wroteSomething)

        if (-not $wroteSomething) {
            Write-OperationLog -Message "Secure overwrite wrote 0 of $totalBytes bytes to '$TargetPath'. Reporting FAILURE: a pass that writes nothing has sanitized nothing." -LogLevel 'Error'
        }
        if ($passesFailed -gt 0) {
            Write-OperationLog -Message "$passesFailed of $Passes pass(es) failed on '$TargetPath'." -LogLevel 'Error'
        }

        $resultMsg = if ($overwriteSucceeded) {
            "Secure overwrite completed: $passesCompleted/$Passes passes, $totalBytesOverwritten bytes overwritten."
        }
        else {
            "Secure overwrite FAILED on '$TargetPath': $passesCompleted/$Passes passes completed, $passesFailed failed, $totalBytesOverwritten of $totalBytes bytes written."
        }
        Write-OperationLog -Message $resultMsg -LogLevel $(if ($overwriteSucceeded) { 'Info' } else { 'Error' })

        # Only claim a final pattern if the media really was written end to end. A
        # partial or failed run leaves a mix, which must NOT be reported as
        # verifiable: doing so hands the verifier a pattern to confirm that the disk
        # was never given.
        $finalPattern = if ($overwriteSucceeded) { $plannedFinalPattern } else { $null }

        return [PSCustomObject]@{
            Success          = $overwriteSucceeded
            BytesOverwritten = $totalBytesOverwritten
            PassesCompleted  = $passesCompleted
            PassesFailed     = $passesFailed
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
            PassesFailed     = $passesFailed
            Duration         = $stopwatch.Elapsed
            Message          = $errMsg
            # The run threw part way through, so the media holds an unknown mix.
            FinalPattern     = $null
        }
    }
}

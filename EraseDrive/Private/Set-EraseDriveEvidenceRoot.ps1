function Set-EraseDriveEvidenceRoot {
    <#
    .SYNOPSIS
        Chooses where logs and destruction certificates are written, and points the module at it.

    .DESCRIPTION
        Defect D2: the module's default evidence location is
        %ProgramData%\DarkHorse\EraseDrive, which is on the machine being wiped. For a
        reissue or resale that is the wrong place twice over. The certificate leaves with
        the asset instead of staying with the operator, and on a wipe thorough enough to be
        worth certifying, the evidence is written to a volume whose contents are being
        destroyed.

        This function resolves an evidence root in preference order and rewrites the
        module's log and certificate paths to point at it:

            1. An explicit -Path from the caller.
            2. The directory the module was launched from. When EraseDrive is run from a
               USB stick this is the stick, which is the correct answer for both live and
               WinPE use.
            3. %ProgramData% on the running system, as a last resort.

        A candidate is only accepted if it is actually writable, proven by writing a probe
        file and deleting it rather than by inspecting ACLs. A read-only or absent stick
        must fall through to the next candidate, not fail at the moment the certificate is
        generated at the end of a long wipe.

        When the chosen root turns out to be on the volume being wiped, that is reported on
        the returned object and logged as a warning. It is not silently accepted, because
        the caller may be about to destroy its own audit trail.

    .PARAMETER Path
        Explicit evidence directory. Overrides auto-detection.

    .PARAMETER Context
        Optional target context from Get-TargetContext. When supplied, the chosen root is
        checked against the target volume and flagged if they are the same.

    .OUTPUTS
        PSCustomObject:
            Success        [bool]
            Root           [string] - Directory chosen
            Source         [string] - Explicit | LaunchDirectory | ProgramData
            OnTargetVolume [bool]   - True when evidence is on the volume being wiped
            Message        [string]

    .EXAMPLE
        Set-EraseDriveEvidenceRoot -Context $ctx
        Auto-detects, preferring the USB stick the module was launched from.

    .EXAMPLE
        Set-EraseDriveEvidenceRoot -Path 'E:\WipeEvidence' -Context $ctx

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path,

        [Parameter()]
        [PSCustomObject]$Context
    )

    # Proves writability by doing it. An ACL check can pass on a read-only volume,
    # a full volume, or a stick that has been physically write-locked.
    $testWritable = {
        param([string]$Candidate)

        # -WhatIf:$false on all three is deliberate. Securing the audit trail is a
        # preflight check, not the operation being previewed, and without it a dry
        # run inherits $WhatIfPreference, every cmdlet below no-ops, and this
        # returns $true having proved nothing. That is the exact failure D2 exists
        # to surface: the operator would be told a read-only, full or physically
        # write-locked location was usable. The probe file is created and removed
        # by this function and nothing else is touched.
        try {
            if (-not (Test-Path -LiteralPath $Candidate)) {
                New-Item -Path $Candidate -ItemType Directory -Force -ErrorAction Stop -WhatIf:$false | Out-Null
            }

            $probe = Join-Path $Candidate ('.ed_write_probe_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            Set-Content -LiteralPath $probe -Value 'probe' -ErrorAction Stop -WhatIf:$false

            # Clean up in a finally-equivalent, and retry once. A probe that is
            # created but not removed leaves litter in a directory the operator did
            # not ask us to write to, and 42 of them accumulated before anyone
            # noticed, because the removal suppressed its own failure. A delete
            # immediately after a create can lose a race with an antivirus scanner
            # holding the new file, so one retry is worth more than one attempt.
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                if (-not (Test-Path -LiteralPath $probe)) { break }
                try {
                    Remove-Item -LiteralPath $probe -Force -ErrorAction Stop -WhatIf:$false
                    break
                }
                catch {
                    if ($attempt -eq 2) {
                        Write-OperationLog -Message "Could not remove the writability probe '$probe': $($_.Exception.Message). It will be left behind." -LogLevel 'WARNING'
                    }
                    else {
                        Start-Sleep -Milliseconds 100
                    }
                }
            }
            return $true
        }
        catch {
            return $false
        }
    }

    # ---- Build the candidate list in preference order ---------------------
    $candidates = [System.Collections.Generic.List[object]]::new()

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $candidates.Add(@{ Root = $Path; Source = 'Explicit' })
    }

    # The directory the module was launched from. ModuleRoot is <launch>\EraseDrive,
    # so its parent is where Start-EraseDrive.ps1 lives: the USB stick, in the
    # intended deployment.
    $moduleRoot = $Script:EraseDriveConfig.ModuleRoot
    if ($moduleRoot) {
        $launchDir = Split-Path -Parent $moduleRoot
        if ($launchDir) {
            $candidates.Add(@{ Root = (Join-Path $launchDir 'EraseDrive-Evidence'); Source = 'LaunchDirectory' })
        }
    }

    $candidates.Add(@{ Root = (Join-Path $env:ProgramData 'DarkHorse\EraseDrive'); Source = 'ProgramData' })

    # ---- Take the first candidate that is genuinely writable --------------
    $chosen = $null
    foreach ($candidate in $candidates) {
        if (& $testWritable $candidate.Root) {
            $chosen = $candidate
            break
        }

        Write-OperationLog -Message "Evidence location '$($candidate.Root)' ($($candidate.Source)) is not writable; trying next candidate." -LogLevel 'WARNING'
    }

    if (-not $chosen) {
        return [PSCustomObject]@{
            Success        = $false
            Root           = $null
            Source         = $null
            OnTargetVolume = $false
            Message        = 'No writable evidence location found. Logs and certificates cannot be persisted.'
        }
    }

    # ---- Flag evidence that would be destroyed by the wipe itself ---------
    $onTarget = $false
    if ($Context -and $Context.Valid) {
        try {
            $evidenceQualifier = (Split-Path -Qualifier (Resolve-Path -LiteralPath $chosen.Root -ErrorAction Stop).Path).ToLowerInvariant()
            $targetQualifier   = (Split-Path -Qualifier $Context.Root).ToLowerInvariant()
            $onTarget = ($evidenceQualifier -eq $targetQualifier)
        }
        catch {
            # A path with no drive qualifier (a UNC share, for example) is not on the
            # target volume by definition, so the default of $false is correct.
            $onTarget = $false
        }
    }

    # ---- Repoint the module ------------------------------------------------
    $Script:EraseDriveConfig.EvidenceRoot  = $chosen.Root
    $Script:EraseDriveConfig.LogDirectory  = $chosen.Root
    $Script:EraseDriveConfig.LogFile       = Join-Path $chosen.Root 'EraseDrive.log'
    $Script:EraseDriveConfig.CertDirectory = Join-Path $chosen.Root 'Certificates'

    if (-not (Test-Path -LiteralPath $Script:EraseDriveConfig.CertDirectory)) {
        New-Item -Path $Script:EraseDriveConfig.CertDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $message = "Evidence root set to '$($chosen.Root)' (source: $($chosen.Source))."
    Write-OperationLog -Message $message -LogLevel 'INFO'

    if ($onTarget) {
        Write-OperationLog -Message "Evidence root '$($chosen.Root)' is on the volume being wiped. The audit trail will not survive this operation. Supply -EvidencePath pointing at removable media." -LogLevel 'WARNING'
    }

    [PSCustomObject]@{
        Success        = $true
        Root           = $chosen.Root
        Source         = $chosen.Source
        OnTargetVolume = $onTarget
        Message        = $message
    }
}

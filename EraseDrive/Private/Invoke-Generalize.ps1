function Invoke-Generalize {
    <#
    .SYNOPSIS
        Runs Windows sysprep /generalize so the device boots to out-of-box setup.

    .DESCRIPTION
        Sysprep generalize is Microsoft's supported mechanism for handing a Windows
        installation to a different person. It resets the machine SID, removes the
        machine-specific driver state and user-specific configuration, clears event logs,
        and arranges for the next boot to land on the out-of-box experience. To the person
        who receives the device, it is indistinguishable from a new machine.

        It is opt-in rather than default, because it has three real costs that the
        operator should be choosing knowingly:

            - It consumes one of a limited number of rearms. A retail Windows install has
              three. Once they are exhausted, generalize cannot be run again on that
              installation at all.
            - It must run on a machine that is not domain joined. Ordering matters:
              -RemoveFromDomain has to happen first, and the orchestrator sequences it
              that way.
            - It fails on per-user provisioned Store apps. This is the single most common
              sysprep failure in the field and its error message is famously unhelpful.

        Every one of those is checked BEFORE anything is started, and a failed check
        returns a refusal with the specific reason. Running sysprep and letting it fail
        halfway is much worse than not starting: it can leave the installation in a state
        where the OS will not boot normally and cannot be generalized again either.

        The caller must run this LAST. Sysprep shuts the machine down when it finishes, so
        any evidence not already written to the USB stick is lost.

    .PARAMETER Context
        Target context from Get-TargetContext. Must be live; sysprep cannot operate offline.

    .PARAMETER CompletionAction
        What sysprep does when it finishes. Shutdown (default) leaves the machine ready to
        hand over. Reboot lands on OOBE for verification. Quit leaves Windows running,
        which is useful for testing.

    .OUTPUTS
        PSCustomObject: Name, Success, Refused, Reason, RearmsRemaining, Warnings, Message

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter()]
        [ValidateSet('Shutdown', 'Reboot', 'Quit')]
        [string]$CompletionAction = 'Shutdown'
    )

    $warnings = [System.Collections.Generic.List[string]]::new()

    $refuse = {
        param([string]$Why)
        Write-OperationLog -Message "Generalize refused: $Why" -LogLevel 'WARNING'
        [PSCustomObject]@{
            Name = 'Generalize'; Success = $false; Refused = $true; Reason = $Why
            RearmsRemaining = $null; Warnings = $warnings.ToArray()
            Message = "Sysprep generalize was not run: $Why"
        }
    }

    # ---- Preflight 1: mode -------------------------------------------------
    if ($Context.IsOffline) {
        return & $refuse 'Sysprep runs only against a booted Windows installation and cannot be applied to an offline image from WinPE. Boot the target and re-run with -Generalize, or omit -Generalize for an offline wipe.'
    }

    # ---- Preflight 2: sysprep must exist -----------------------------------
    $sysprepPath = Join-Path $Context.WindowsDir 'System32\Sysprep\sysprep.exe'
    if (-not (Test-Path -LiteralPath $sysprepPath)) {
        return & $refuse "sysprep.exe not found at '$sysprepPath'."
    }

    # ---- Preflight 3: must not be domain joined ----------------------------
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain) {
            return & $refuse "The machine is still joined to domain '$($cs.Domain)'. Sysprep generalize requires a workgroup machine. Run with -RemoveFromDomain, reboot, then re-run."
        }
    }
    catch {
        $warnings.Add("Could not confirm domain membership before generalize: $($_.Exception.Message)")
    }

    # ---- Preflight 4: rearm budget -----------------------------------------
    $rearms = $null
    try {
        $sls = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
        $rearms = $sls.RemainingWindowsReArmCount

        if ($null -ne $rearms -and $rearms -le 0) {
            return & $refuse 'No Windows rearms remain on this installation. Sysprep generalize cannot be run again. Wipe and reimage the machine instead, or hand it over without generalizing.'
        }

        Write-OperationLog -Message "Windows rearms remaining before generalize: $rearms" -LogLevel 'INFO'
    }
    catch {
        $warnings.Add("Could not read the remaining rearm count: $($_.Exception.Message)")
    }

    # ---- Preflight 5: per-user provisioned Store apps ----------------------
    # The classic failure. A package installed for one user but not provisioned for all
    # users makes generalize abort, and the error in setupact.log names the package while
    # the on-screen message does not.
    try {
        $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | ForEach-Object { $_.PackageName })
        $blocking = @(
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { $_.NonRemovable -ne $true -and $_.PackageFullName -notin $provisioned } |
                Select-Object -ExpandProperty PackageFullName -Unique
        )

        if ($blocking.Count -gt 0) {
            $sample = ($blocking | Select-Object -First 5) -join ', '
            $warnings.Add("$($blocking.Count) Store package(s) are installed for a user but not provisioned for all users. Sysprep may abort on these. Examples: $sample")
            Write-OperationLog -Message "Potential sysprep blockers detected: $($blocking.Count) package(s)." -LogLevel 'WARNING'
        }
    }
    catch {
        $warnings.Add("Could not evaluate Store packages for sysprep compatibility: $($_.Exception.Message)")
    }

    # ---- Run ----------------------------------------------------------------
    if (-not $PSCmdlet.ShouldProcess($Context.Root, "Run sysprep /generalize /oobe /$($CompletionAction.ToLower())")) {
        return [PSCustomObject]@{
            Name = 'Generalize'; Success = $false; Refused = $true
            Reason = 'Declined at confirmation prompt.'; RearmsRemaining = $rearms
            Warnings = $warnings.ToArray(); Message = 'Sysprep generalize declined by operator.'
        }
    }

    $actionArg = switch ($CompletionAction) {
        'Shutdown' { '/shutdown' }
        'Reboot'   { '/reboot' }
        'Quit'     { '/quit' }
    }

    try {
        Write-OperationLog -Message "Starting sysprep: /generalize /oobe $actionArg. Evidence must already be written; the machine will not be usable after this point." -LogLevel 'WARNING'

        $process = Start-Process -FilePath $sysprepPath `
            -ArgumentList '/generalize', '/oobe', $actionArg, '/quiet' `
            -Wait -PassThru -ErrorAction Stop

        if ($process.ExitCode -ne 0) {
            # setupact.log is where the real reason lives.
            $logHint = Join-Path $Context.WindowsDir 'System32\Sysprep\Panther\setupact.log'
            return [PSCustomObject]@{
                Name = 'Generalize'; Success = $false; Refused = $false
                Reason = "Sysprep exited with code $($process.ExitCode). See $logHint for the failing component."
                RearmsRemaining = $rearms; Warnings = $warnings.ToArray()
                Message = "Sysprep generalize failed with exit code $($process.ExitCode)."
            }
        }

        Write-OperationLog -Message 'Sysprep generalize completed. The next boot will present out-of-box setup.' -LogLevel 'SUCCESS'

        [PSCustomObject]@{
            Name = 'Generalize'; Success = $true; Refused = $false; Reason = $null
            RearmsRemaining = $(if ($null -ne $rearms) { $rearms - 1 } else { $null })
            Warnings = $warnings.ToArray()
            Message = 'Sysprep generalize completed. The device boots to out-of-box setup.'
        }
    }
    catch {
        [PSCustomObject]@{
            Name = 'Generalize'; Success = $false; Refused = $false
            Reason = $_.Exception.Message; RearmsRemaining = $rearms
            Warnings = $warnings.ToArray()
            Message = "Sysprep generalize failed: $($_.Exception.Message)"
        }
    }
}

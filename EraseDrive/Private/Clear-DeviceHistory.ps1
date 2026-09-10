function Clear-DeviceHistory {
    <#
    .SYNOPSIS
        Removes the machine-level usage history that outlives any individual user profile.

    .DESCRIPTION
        The records here are what make a wiped machine still look obviously second-hand,
        and several of them name the previous user or the company directly.

            - USBSTOR and the MountedDevices map: every removable device ever attached,
              by vendor, model and serial, with the drive letters they were given. On a
              machine being sold this is a list of the previous owner's other hardware.
            - ActivitiesCache, the Windows Timeline database: application and document
              history across sessions.
            - Windows.old: an entire previous Windows installation including its complete
              Users directory. This one is the largest single miss possible, because a
              machine that was upgraded rather than clean-installed can hold a full second
              copy of every profile the wipe just carefully removed.
            - Windows Error Reporting queues, which contain process memory dumps.
            - Windows Update and Delivery Optimization caches.
            - Cached Group Policy, which names the company's OUs and policy objects.
            - Prefetch, which records which applications were run.

        Windows.old is deleted rather than left for Disk Cleanup, because Disk Cleanup is
        not guaranteed to run and not guaranteed to select it.

    .PARAMETER Context
        Target context from Get-TargetContext.

    .OUTPUTS
        PSCustomObject: Name, Success, ItemsRemoved, Warnings, Message

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $warnings = [System.Collections.Generic.List[string]]::new()
    $removed  = 0
    $success  = $true

    if (-not $PSCmdlet.ShouldProcess($Context.Root, 'Remove device usage history')) {
        return [PSCustomObject]@{
            Name = 'DeviceHistory'; Success = $true; ItemsRemoved = 0
            Warnings = @(); Message = 'Declined at confirmation prompt.'
        }
    }

    # ---- 1. Filesystem history -------------------------------------------
    $directories = @(
        @{ Path = (Join-Path $Context.Root 'Windows.old'); Label = 'previous Windows installation'; DeleteRoot = $true },
        @{ Path = (Join-Path $Context.WindowsDir 'Prefetch'); Label = 'application prefetch'; DeleteRoot = $false },
        @{ Path = (Join-Path $Context.WindowsDir 'Temp'); Label = 'system temp'; DeleteRoot = $false },
        @{ Path = (Join-Path $Context.WindowsDir 'SoftwareDistribution\Download'); Label = 'Windows Update cache'; DeleteRoot = $false },
        @{ Path = (Join-Path $Context.ProgramDataDir 'Microsoft\Windows\WER'); Label = 'error reporting queues'; DeleteRoot = $false },
        @{ Path = (Join-Path $Context.ProgramDataDir 'Microsoft\Network\Downloader'); Label = 'delivery optimization cache'; DeleteRoot = $false },
        @{ Path = (Join-Path $Context.ProgramDataDir 'Microsoft\Windows\Recent'); Label = 'recent items'; DeleteRoot = $false },
        @{ Path = (Join-Path $Context.WindowsDir 'System32\GroupPolicy'); Label = 'cached machine group policy'; DeleteRoot = $true },
        @{ Path = (Join-Path $Context.WindowsDir 'System32\GroupPolicyUsers'); Label = 'cached user group policy'; DeleteRoot = $true },
        @{ Path = (Join-Path $Context.ProgramDataDir 'Microsoft\Group Policy\History'); Label = 'group policy history'; DeleteRoot = $true }
    )

    foreach ($entry in $directories) {
        if (-not (Test-Path -LiteralPath $entry.Path)) { continue }

        try {
            if (-not $Context.IsOffline) {
                & takeown.exe /f "$($entry.Path)" /r /d y 2>&1 | Out-Null
                & icacls.exe "$($entry.Path)" /grant administrators:F /t /c /q 2>&1 | Out-Null
            }

            if ($entry.DeleteRoot) {
                Remove-Item -LiteralPath $entry.Path -Recurse -Force -ErrorAction Stop
            }
            else {
                Get-ChildItem -LiteralPath $entry.Path -Force -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }

            $removed++
            Write-OperationLog -Message "Cleared $($entry.Label): $($entry.Path)" -LogLevel 'INFO'
        }
        catch {
            # A live run cannot clear everything under Windows\Temp because files are open.
            # That is expected and is not a failure of the operation.
            $warnings.Add("Could not fully clear $($entry.Label) at '$($entry.Path)': $($_.Exception.Message)")
        }
    }

    # ---- 2. Timeline database, which lives inside each profile ------------
    # Profiles are normally gone by the time this runs, but a live wipe leaves the
    # operator's profile in place and an interrupted run may leave others.
    if (Test-Path -LiteralPath $Context.UsersDir) {
        try {
            Get-ChildItem -LiteralPath $Context.UsersDir -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $activities = Join-Path $_.FullName 'AppData\Local\ConnectedDevicesPlatform'
                if (Test-Path -LiteralPath $activities) {
                    Get-ChildItem -LiteralPath $activities -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                    $removed++
                }
            }
        }
        catch {
            $warnings.Add("Could not clear Timeline databases: $($_.Exception.Message)")
        }
    }

    # ---- 3. Attached-device history in the registry ------------------------
    $deviceHistory = Invoke-WithRegistryHive -Context $Context -Hive SYSTEM -ScriptBlock {
        param($root)

        $controlSet = Get-ControlSetPath -HiveRoot $root -IsOffline $Context.IsOffline
        if (-not $controlSet) { return -1 }

        $count = 0

        # Every removable device ever attached, by vendor, product and serial.
        foreach ($enumPath in @('Enum\USBSTOR', 'Enum\WpdBusEnumRoot')) {
            $key = Join-Path $controlSet $enumPath
            if (Test-Path -LiteralPath $key) {
                Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-Item -LiteralPath $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    $count++
                }
            }
        }

        # The volume-to-drive-letter map, which retains entries for devices long gone.
        $mounted = Join-Path $controlSet 'Control\MountedDevices'
        if (Test-Path -LiteralPath $mounted) {
            $props = Get-ItemProperty -LiteralPath $mounted -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties |
                    Where-Object { $_.Name -match '^\\(DosDevices|\?\?)\\' } |
                    ForEach-Object {
                        Remove-ItemProperty -LiteralPath $mounted -Name $_.Name -Force -ErrorAction SilentlyContinue
                        $count++
                    }
            }
        }

        $count
    }

    if ($deviceHistory.Success -and [int]$deviceHistory.Result -ge 0) {
        $removed += [int]$deviceHistory.Result
        Write-OperationLog -Message "Removed $($deviceHistory.Result) attached-device history record(s)." -LogLevel 'INFO'
    }
    else {
        $success = $false
        $warnings.Add("Could not clear attached-device history: $($deviceHistory.Message)")
    }

    [PSCustomObject]@{
        Name         = 'DeviceHistory'
        Success      = $success
        ItemsRemoved = $removed
        Warnings     = $warnings.ToArray()
        Message      = "Removed $removed device history artifact(s)."
    }
}

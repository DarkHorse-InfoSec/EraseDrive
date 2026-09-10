function New-EraseDriveBootMedia {
    <#
    .SYNOPSIS
        Builds a bootable WinPE USB stick that runs EraseDrive against an offline Windows install.

    .DESCRIPTION
        Produces the media that makes a complete reissue wipe possible. Booting the target
        from this stick means the Windows installation being wiped is not running, which
        removes every structural limit a live wipe has: there is no operator profile to
        preserve, the registry hives are ordinary files rather than locked kernel objects,
        HKLM\SECURITY can be mounted and its cached domain credentials destroyed, and
        pagefile.sys and hiberfil.sys can simply be deleted.

        The build:
            1. Locates the Windows ADK and the WinPE add-on.
            2. Creates a WinPE working set with copype.
            3. Mounts boot.wim and adds the optional components the module needs.
            4. Copies the EraseDrive module onto the image.
            5. Writes a startnet.cmd that lands the operator in a PowerShell session with
               the module already imported.
            6. Unmounts and commits, then writes the USB with MakeWinPEMedia.

        ABOUT BITLOCKER. A corporate device is usually encrypted, and an encrypted volume
        is not readable from WinPE until it is unlocked. The image therefore includes
        WinPE-SecureStartup so manage-bde is available, and the boot script says so. The
        recovery key or password is the operator's to supply; this tool cannot and should
        not try to bypass it. A wipe run against a still-locked volume would find no
        Windows installation and refuse, which is the correct behaviour but is confusing
        if you do not know why.

        THE USB IS FORMATTED. MakeWinPEMedia /UFD erases the target stick completely.
        The target is validated as removable before anything is written, and a fixed disk
        is refused outright rather than confirmed, because the cost of getting that wrong
        is somebody's data.

    .PARAMETER UsbDriveLetter
        Drive letter of the USB stick to write, for example 'E'. The stick is erased.
        Omit with -IsoPath to build an ISO instead.

    .PARAMETER IsoPath
        Build a bootable ISO at this path instead of writing a USB stick.

    .PARAMETER WorkingDirectory
        Scratch directory for the WinPE build. Defaults to a temporary directory. Needs
        roughly 2 GB free and must be on a local NTFS volume.

    .PARAMETER Architecture
        WinPE architecture. amd64 by default; use arm64 for ARM devices.

    .PARAMETER KeepWorkingDirectory
        Leave the scratch directory in place after the build for inspection.

    .OUTPUTS
        PSCustomObject: Success, MediaType, Target, WorkingDirectory, Components, Message

    .EXAMPLE
        New-EraseDriveBootMedia -UsbDriveLetter E

        Builds the boot stick on E:. E: is erased.

    .EXAMPLE
        New-EraseDriveBootMedia -IsoPath 'D:\EraseDrivePE.iso'

        Builds an ISO for a virtual machine or for out-of-band management.

    .NOTES
        Requires the Windows ADK with the WinPE add-on, and an elevated session.
        Download: https://learn.microsoft.com/windows-hardware/get-started/adk-install
        Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Usb')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Usb')]
        [ValidatePattern('^[A-Za-z]$')]
        [string]$UsbDriveLetter,

        [Parameter(Mandatory, ParameterSetName = 'Iso')]
        [ValidateNotNullOrEmpty()]
        [string]$IsoPath,

        [Parameter()]
        [string]$WorkingDirectory,

        [Parameter()]
        [ValidateSet('amd64', 'arm64')]
        [string]$Architecture = 'amd64',

        [Parameter()]
        [switch]$KeepWorkingDirectory
    )

    $fail = {
        param([string]$Why)
        Write-OperationLog -Message "Boot media build failed: $Why" -LogLevel 'ERROR'
        [PSCustomObject]@{
            Success = $false; MediaType = $PSCmdlet.ParameterSetName; Target = $null
            WorkingDirectory = $WorkingDirectory; Components = @(); Message = $Why
        }
    }

    # ---- 1. Locate the ADK and the WinPE add-on ---------------------------
    $adkRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit",
        "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit"
    )

    $peRoot = $null
    foreach ($root in $adkRoots) {
        $candidate = Join-Path $root "Windows Preinstallation Environment"
        if (Test-Path -LiteralPath (Join-Path $candidate 'copype.cmd')) {
            $peRoot = $candidate
            break
        }
    }

    if (-not $peRoot) {
        return & $fail (
            'The Windows ADK WinPE add-on was not found. Install the Windows ADK and the ' +
            '"Windows PE add-on for the Windows ADK", both from ' +
            'https://learn.microsoft.com/windows-hardware/get-started/adk-install, then re-run. ' +
            "Looked in: $($adkRoots -join '; ')"
        )
    }

    $copype        = Join-Path $peRoot 'copype.cmd'
    $makeWinPEMedia = Join-Path $peRoot 'MakeWinPEMedia.cmd'
    $ocRoot        = Join-Path $peRoot "$Architecture\WinPE_OCs"

    if (-not (Test-Path -LiteralPath $ocRoot)) {
        return & $fail "WinPE optional components not found at '$ocRoot'. The WinPE add-on may be partially installed."
    }

    Write-OperationLog -Message "Windows ADK WinPE found at: $peRoot" -LogLevel 'INFO'

    # ---- 2. Validate the target ------------------------------------------
    $targetDescription = $null

    if ($PSCmdlet.ParameterSetName -eq 'Usb') {
        $driveId = "$($UsbDriveLetter.ToUpper()):"

        try {
            $volume = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID = '$driveId'" -ErrorAction Stop
        }
        catch {
            return & $fail "Could not query drive ${driveId}: $($_.Exception.Message)"
        }

        if (-not $volume) {
            return & $fail "Drive $driveId was not found. Insert the USB stick and check the letter."
        }

        # DriveType 2 is removable. A fixed disk is refused rather than confirmed: this
        # step formats the target, and "are you sure" is not an adequate guard against
        # naming the wrong letter when the wrong letter might be a data drive.
        if ($volume.DriveType -ne 2) {
            $typeName = switch ([int]$volume.DriveType) {
                3 { 'a fixed local disk' }
                4 { 'a network drive' }
                5 { 'an optical drive' }
                default { "drive type $($volume.DriveType)" }
            }
            return & $fail (
                "Refusing to build boot media on $driveId because it is $typeName, not removable media. " +
                'MakeWinPEMedia erases the target completely. Use a USB stick, or build an ISO with -IsoPath.'
            )
        }

        $sizeGB = [math]::Round($volume.Size / 1GB, 2)
        if ($volume.Size -lt 1GB) {
            return & $fail "Drive $driveId is only $sizeGB GB. WinPE media needs at least 1 GB."
        }

        $targetDescription = "$driveId ($($volume.VolumeName), $sizeGB GB removable)"
    }
    else {
        $isoParent = Split-Path -Parent $IsoPath
        if ($isoParent -and -not (Test-Path -LiteralPath $isoParent)) {
            return & $fail "The directory for the ISO does not exist: $isoParent"
        }
        $targetDescription = $IsoPath
    }

    # ---- 3. Working directory ---------------------------------------------
    if (-not $WorkingDirectory) {
        $WorkingDirectory = Join-Path $env:TEMP ("EraseDrivePE_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    # copype refuses to run into an existing directory.
    if (Test-Path -LiteralPath $WorkingDirectory) {
        return & $fail "Working directory '$WorkingDirectory' already exists. copype requires a path that does not exist yet."
    }

    if (-not $PSCmdlet.ShouldProcess($targetDescription, "Build EraseDrive WinPE boot media (this ERASES the target)")) {
        return [PSCustomObject]@{
            Success = $false; MediaType = $PSCmdlet.ParameterSetName; Target = $targetDescription
            WorkingDirectory = $null; Components = @(); Message = 'Declined at confirmation prompt.'
        }
    }

    $mountPath = Join-Path $WorkingDirectory 'mount'
    $installedComponents = [System.Collections.Generic.List[string]]::new()
    $mounted = $false

    try {
        # ---- 4. Create the WinPE working set -----------------------------
        Write-OperationLog -Message "Creating WinPE working set at $WorkingDirectory" -LogLevel 'INFO'

        $copyOutput = & cmd.exe /c "`"$copype`" $Architecture `"$WorkingDirectory`"" 2>&1
        if ($LASTEXITCODE -ne 0) {
            return & $fail "copype failed: $copyOutput"
        }

        $bootWim = Join-Path $WorkingDirectory 'media\sources\boot.wim'
        if (-not (Test-Path -LiteralPath $bootWim)) {
            return & $fail "copype completed but boot.wim was not produced at '$bootWim'."
        }

        # ---- 5. Mount the image -------------------------------------------
        if (-not (Test-Path -LiteralPath $mountPath)) {
            New-Item -Path $mountPath -ItemType Directory -Force | Out-Null
        }

        Write-OperationLog -Message 'Mounting boot.wim' -LogLevel 'INFO'
        Mount-WindowsImage -ImagePath $bootWim -Index 1 -Path $mountPath -ErrorAction Stop | Out-Null
        $mounted = $true

        # ---- 6. Add the optional components -------------------------------
        # Order is not arbitrary. WMI underpins the rest, NetFx underpins PowerShell,
        # and each component's language pack must follow its own package.
        $components = @(
            'WinPE-WMI',            # required by NetFx and by Get-CimInstance
            'WinPE-NetFX',          # required by PowerShell
            'WinPE-Scripting',      # WSH, required by several ADK helpers
            'WinPE-PowerShell',     # the module itself
            'WinPE-StorageWMI',     # Get-Disk, Get-Volume, Clear-Disk
            'WinPE-DismCmdlets',    # servicing cmdlets
            'WinPE-SecureStartup',  # manage-bde, for unlocking BitLocker volumes
            'WinPE-EnhancedStorage' # encrypted and enhanced-storage device support
        )

        foreach ($component in $components) {
            $cab = Join-Path $ocRoot "$component.cab"
            if (-not (Test-Path -LiteralPath $cab)) {
                Write-OperationLog -Message "Optional component not present, skipping: $cab" -LogLevel 'WARNING'
                continue
            }

            Add-WindowsPackage -Path $mountPath -PackagePath $cab -ErrorAction Stop | Out-Null
            $installedComponents.Add($component)

            # The matching language pack, where one exists.
            $langCab = Join-Path $ocRoot "en-us\${component}_en-us.cab"
            if (Test-Path -LiteralPath $langCab) {
                Add-WindowsPackage -Path $mountPath -PackagePath $langCab -ErrorAction Stop | Out-Null
            }

            Write-OperationLog -Message "Added component: $component" -LogLevel 'INFO'
        }

        # ---- 7. Copy the module into the image -----------------------------
        $moduleSource = $Script:EraseDriveConfig.ModuleRoot
        $launcherSource = Join-Path (Split-Path -Parent $moduleSource) 'Start-EraseDrive.ps1'
        $imageToolPath = Join-Path $mountPath 'EraseDrive'

        New-Item -Path $imageToolPath -ItemType Directory -Force | Out-Null
        Copy-Item -Path $moduleSource -Destination $imageToolPath -Recurse -Force -ErrorAction Stop

        if (Test-Path -LiteralPath $launcherSource) {
            Copy-Item -Path $launcherSource -Destination $imageToolPath -Force -ErrorAction Stop
        }

        Write-OperationLog -Message "Copied the EraseDrive module into the image at X:\EraseDrive" -LogLevel 'INFO'

        # ---- 8. Boot scripts ------------------------------------------------
        # startnet.cmd runs wpeinit (which brings up devices and networking) and then
        # hands the operator a PowerShell session with the module already loaded.
        $startnet = @'
@echo off
wpeinit
echo.
echo ================================================================
echo  EraseDrive WinPE - offline device reissue and resale wipe
echo ================================================================
echo.
powershell.exe -NoLogo -NoExit -ExecutionPolicy Bypass -File X:\EraseDrive\Start-EraseDrivePE.ps1
'@

        Set-Content -Path (Join-Path $mountPath 'Windows\System32\startnet.cmd') -Value $startnet -Encoding Ascii -Force

        # The operator-facing script. Deliberately does not start a wipe on its own:
        # it reports what it found and waits for an explicit command.
        $peScript = @'
# EraseDrive WinPE session bootstrap.
# Imports the module and reports the volumes present. Starts nothing on its own.

$ErrorActionPreference = 'Continue'

Import-Module X:\EraseDrive\EraseDrive -Force

Write-Host ""
Write-Host "EraseDrive is loaded. Volumes visible to WinPE:" -ForegroundColor Cyan
Write-Host ""

Get-Volume |
    Where-Object { $_.DriveLetter } |
    Sort-Object DriveLetter |
    Format-Table DriveLetter, FileSystemLabel, FileSystem,
        @{ N = 'Size(GB)'; E = { [math]::Round($_.Size / 1GB, 1) } },
        HealthStatus -AutoSize

# A BitLocker-locked volume cannot be read, and the wipe will correctly refuse it.
# Say so up front rather than letting the operator discover it as a confusing error.
$locked = @()
try {
    $locked = @(Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
        $status = & manage-bde.exe -status "$($_.DriveLetter):" 2>&1
        if ($status -match 'Lock Status:\s*Locked') { $_.DriveLetter }
    })
}
catch { }

if ($locked.Count -gt 0) {
    Write-Host "BitLocker-LOCKED volumes: $($locked -join ', ')" -ForegroundColor Yellow
    Write-Host "Unlock before wiping, for example:" -ForegroundColor Yellow
    Write-Host "    manage-bde -unlock $($locked[0]): -RecoveryPassword <48-digit key>" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "To wipe the internal Windows installation for reissue or resale:" -ForegroundColor Green
Write-Host ""
Write-Host "    Invoke-DeviceReissueWipe -OfflineRoot C:\ -RemoveFromDomain -WipeMethod Secure" -ForegroundColor White
Write-Host ""
Write-Host "Preview without changing anything by adding -WhatIf." -ForegroundColor Gray
Write-Host "Confirm C:\ is the Windows volume in the table above; WinPE letters can differ." -ForegroundColor Gray
Write-Host ""
'@

        Set-Content -Path (Join-Path $imageToolPath 'Start-EraseDrivePE.ps1') -Value $peScript -Encoding UTF8 -Force

        # ---- 9. Commit -------------------------------------------------------
        Write-OperationLog -Message 'Committing changes and unmounting the image' -LogLevel 'INFO'
        Dismount-WindowsImage -Path $mountPath -Save -ErrorAction Stop | Out-Null
        $mounted = $false

        # ---- 10. Write the media --------------------------------------------
        if ($PSCmdlet.ParameterSetName -eq 'Usb') {
            $driveId = "$($UsbDriveLetter.ToUpper()):"
            Write-OperationLog -Message "Writing boot media to $driveId. The stick is being erased." -LogLevel 'WARNING'

            $mediaOutput = & cmd.exe /c "echo Y| `"$makeWinPEMedia`" /UFD `"$WorkingDirectory`" $driveId" 2>&1
            if ($LASTEXITCODE -ne 0) {
                return & $fail "MakeWinPEMedia failed writing to ${driveId}: $mediaOutput"
            }
        }
        else {
            Write-OperationLog -Message "Building ISO at $IsoPath" -LogLevel 'INFO'

            $mediaOutput = & cmd.exe /c "`"$makeWinPEMedia`" /ISO `"$WorkingDirectory`" `"$IsoPath`"" 2>&1
            if ($LASTEXITCODE -ne 0) {
                return & $fail "MakeWinPEMedia failed building the ISO: $mediaOutput"
            }
        }

        Write-OperationLog -Message "Boot media created: $targetDescription" -LogLevel 'SUCCESS'
        Write-AuditLog -EventType 'OperationCompleted' -Message "EraseDrive WinPE boot media built" -TargetDescription $targetDescription

        [PSCustomObject]@{
            Success          = $true
            MediaType        = $PSCmdlet.ParameterSetName
            Target           = $targetDescription
            WorkingDirectory = $(if ($KeepWorkingDirectory) { $WorkingDirectory } else { $null })
            Components       = $installedComponents.ToArray()
            Message          = "EraseDrive WinPE boot media created on $targetDescription with $($installedComponents.Count) optional component(s)."
        }
    }
    catch {
        & $fail $_.Exception.Message
    }
    finally {
        # A mounted image left behind locks the working directory and blocks the next
        # build, so discard it explicitly rather than relying on the process exiting.
        if ($mounted) {
            try {
                Dismount-WindowsImage -Path $mountPath -Discard -ErrorAction SilentlyContinue | Out-Null
                Write-OperationLog -Message 'Discarded the mounted image after a failed build.' -LogLevel 'WARNING'
            }
            catch { }
        }

        if (-not $KeepWorkingDirectory -and (Test-Path -LiteralPath $WorkingDirectory)) {
            Remove-Item -LiteralPath $WorkingDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

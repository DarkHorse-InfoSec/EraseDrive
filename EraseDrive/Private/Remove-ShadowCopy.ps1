function Remove-ShadowCopy {
    <#
    .SYNOPSIS
        Deletes Volume Shadow Copies and System Restore points, and stops new ones being created.

    .DESCRIPTION
        The highest-value item in the reissue wipe, and the one most often missed.

        A shadow copy is a point-in-time image of the volume. Deleting a user's profile
        does nothing to a shadow copy taken while that profile was populated: the
        documents, the browser profile, the cached credentials and the registry hives are
        all still there, byte for byte, and are recoverable with nothing more exotic than
        a right-click on Previous Versions. Any wipe that leaves shadow copies behind has
        not removed the data, it has removed one copy of the data.

        System Restore is disabled after the deletion rather than before. Disabling it
        first is the intuitive order and it is wrong: on some builds disabling the service
        leaves existing shadow storage allocated but no longer enumerable through the
        normal interfaces, which makes it harder to confirm the deletion actually
        happened.

        Offline mode cannot use the VSS APIs, because the VSS service belongs to the
        offline install and is not running. It deletes the shadow storage files directly
        out of System Volume Information and disables System Restore in the offline
        registry, then reports what it could not remove rather than assuming success.

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

    if (-not $PSCmdlet.ShouldProcess($Context.Root, 'Delete all shadow copies and restore points')) {
        return [PSCustomObject]@{
            Name = 'ShadowCopies'; Success = $true; ItemsRemoved = 0
            Warnings = @(); Message = 'Declined at confirmation prompt.'
        }
    }

    if (-not $Context.IsOffline) {
        # ---- Live: delete through the VSS API, then verify ----------------
        try {
            $shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue)
            $before  = $shadows.Count

            foreach ($shadow in $shadows) {
                try {
                    Remove-CimInstance -InputObject $shadow -ErrorAction Stop
                    $removed++
                }
                catch {
                    $warnings.Add("Could not delete shadow copy $($shadow.ID): $($_.Exception.Message)")
                }
            }

            Write-OperationLog -Message "Deleted $removed of $before shadow copies via the VSS API." -LogLevel 'INFO'

            # vssadmin catches storage the CIM class does not enumerate on some builds.
            & vssadmin.exe delete shadows /all /quiet 2>&1 | Out-Null

            # Verify rather than trust. This is the whole point of the step.
            $remaining = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue).Count
            if ($remaining -gt 0) {
                $success = $false
                $warnings.Add("$remaining shadow copies still present after deletion. Prior user data remains recoverable from them.")
                Write-OperationLog -Message "$remaining shadow copies survived deletion." -LogLevel 'ERROR'
            }
        }
        catch {
            $success = $false
            $warnings.Add("Shadow copy deletion failed: $($_.Exception.Message)")
        }

        # ---- Disable System Restore so nothing is recreated ---------------
        try {
            Disable-ComputerRestore -Drive $Context.Root -ErrorAction Stop
            Write-OperationLog -Message "System Restore disabled on $($Context.Root)" -LogLevel 'INFO'
        }
        catch {
            $warnings.Add("Could not disable System Restore: $($_.Exception.Message)")
        }
    }
    else {
        # ---- Offline: delete shadow storage from System Volume Information ----
        # Shadow storage files carry the VSS differential-area GUID in their name.
        $sviPath = Join-Path $Context.Root 'System Volume Information'

        if (Test-Path -LiteralPath $sviPath) {
            # WinPE runs as SYSTEM but System Volume Information denies even SYSTEM by
            # default, so ownership has to be taken before the files are enumerable.
            & takeown.exe /f "$sviPath" /r /d y 2>&1 | Out-Null
            & icacls.exe "$sviPath" /grant administrators:F /t /c /q 2>&1 | Out-Null

            try {
                $shadowFiles = @(
                    Get-ChildItem -LiteralPath $sviPath -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '3808876B-C176-4E48-B7AE-04046E6CC752' }
                )

                foreach ($file in $shadowFiles) {
                    try {
                        Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                        $removed++
                    }
                    catch {
                        $success = $false
                        $warnings.Add("Could not delete shadow storage '$($file.Name)': $($_.Exception.Message)")
                    }
                }

                Write-OperationLog -Message "Removed $removed shadow storage file(s) from $sviPath" -LogLevel 'INFO'
            }
            catch {
                $success = $false
                $warnings.Add("Could not enumerate shadow storage under '$sviPath': $($_.Exception.Message)")
            }
        }
        else {
            $warnings.Add("No System Volume Information directory at '$sviPath'; nothing to delete.")
        }

        # ---- Disable System Restore in the offline registry ---------------
        $disable = Invoke-WithRegistryHive -Context $Context -Hive SOFTWARE -ScriptBlock {
            param($root)

            $key = Join-Path $root 'Microsoft\Windows NT\CurrentVersion\SystemRestore'
            if (-not (Test-Path -LiteralPath $key)) {
                New-Item -Path $key -Force -ErrorAction SilentlyContinue | Out-Null
            }

            Set-ItemProperty -LiteralPath $key -Name 'DisableSR' -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -LiteralPath $key -Name 'DisableConfig' -Value 1 -Type DWord -ErrorAction SilentlyContinue
            $true
        }

        if (-not $disable.Success) {
            $warnings.Add("Could not disable System Restore in the offline registry: $($disable.Message)")
        }
    }

    [PSCustomObject]@{
        Name         = 'ShadowCopies'
        Success      = $success
        ItemsRemoved = $removed
        Warnings     = $warnings.ToArray()
        Message      = "Removed $removed shadow copy artifact(s)."
    }
}

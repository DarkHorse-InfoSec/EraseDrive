function Clear-PageAndHibernation {
    <#
    .SYNOPSIS
        Removes the pagefile, hibernation file and swapfile, and stops them being repopulated.

    .DESCRIPTION
        pagefile.sys and hiberfil.sys are unstructured images of physical memory. Whatever
        was in RAM can be in them: documents, decrypted content, tokens, key material,
        fragments of anything the previous user had open. hiberfil.sys is the more
        exposed of the two, because it is a deliberate whole-memory snapshot rather than
        an eviction artifact.

        A very important asymmetry between the two modes, and the clearest illustration of
        why the WinPE path exists:

            Offline - both files are ordinary files on a volume nobody is using. They are
                      deleted outright and the removal is verified.
            Live    - the running kernel holds both open. Nothing can delete them. The best
                      a live run can do is turn hibernation off, deconfigure the pagefile,
                      and set ClearPageFileAtShutdown so the contents are zeroed on the
                      next clean shutdown.

        The live path therefore reports Success = $true with PendingReboot = $true, and the
        caller must surface that. It is not a completed removal and must never be reported
        as one. A machine handed over without that reboot still has the previous user's
        memory contents on disk.

    .PARAMETER Context
        Target context from Get-TargetContext.

    .OUTPUTS
        PSCustomObject: Name, Success, ItemsRemoved, PendingReboot, Warnings, Message

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $warnings      = [System.Collections.Generic.List[string]]::new()
    $removed       = 0
    $success       = $true
    $pendingReboot = $false

    if (-not $PSCmdlet.ShouldProcess($Context.Root, 'Remove pagefile, hibernation file and swapfile')) {
        return [PSCustomObject]@{
            Name = 'PageAndHibernation'; Success = $true; ItemsRemoved = 0
            PendingReboot = $false; Warnings = @(); Message = 'Declined at confirmation prompt.'
        }
    }

    if ($Context.IsOffline) {
        # ---- Offline: they are just files -------------------------------------
        foreach ($fileName in @('pagefile.sys', 'hiberfil.sys', 'swapfile.sys')) {
            $path = Join-Path $Context.Root $fileName

            if (Test-Path -LiteralPath $path) {
                try {
                    # These carry the hidden and system attributes, which blocks deletion
                    # until they are cleared.
                    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                    $item.Attributes = 'Normal'
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop

                    if (Test-Path -LiteralPath $path) {
                        $success = $false
                        $warnings.Add("$fileName still present after deletion.")
                    }
                    else {
                        $removed++
                        Write-OperationLog -Message "Deleted $path" -LogLevel 'INFO'
                    }
                }
                catch {
                    $success = $false
                    $warnings.Add("Could not delete ${fileName}: $($_.Exception.Message)")
                }
            }
        }

        # ---- Stop them coming back on the next boot -----------------------
        $reg = Invoke-WithRegistryHive -Context $Context -Hive SYSTEM -ScriptBlock {
            param($root)

            $controlSet = Get-ControlSetPath -HiveRoot $root -IsOffline $true
            if (-not $controlSet) { return $false }

            $memoryKey = Join-Path $controlSet 'Control\Session Manager\Memory Management'
            if (Test-Path -LiteralPath $memoryKey) {
                # Zero the pagefile on every future shutdown, and clear any configured
                # pagefile so the next boot does not immediately recreate one holding
                # data from the machine's new life before it is even handed over.
                Set-ItemProperty -LiteralPath $memoryKey -Name 'ClearPageFileAtShutdown' -Value 1 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -LiteralPath $memoryKey -Name 'PagingFiles' -Value @() -Type MultiString -ErrorAction SilentlyContinue
            }

            $powerKey = Join-Path $controlSet 'Control\Power'
            if (Test-Path -LiteralPath $powerKey) {
                Set-ItemProperty -LiteralPath $powerKey -Name 'HibernateEnabled' -Value 0 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -LiteralPath $powerKey -Name 'HibernateEnabledDefault' -Value 0 -Type DWord -ErrorAction SilentlyContinue
            }

            $true
        }

        if (-not $reg.Success -or -not $reg.Result) {
            $warnings.Add("Could not write offline pagefile and hibernation settings: $($reg.Message)")
        }
    }
    else {
        # ---- Live: deconfigure and schedule, because deletion is impossible ----
        $pendingReboot = $true

        try {
            # powercfg /h off deletes hiberfil.sys immediately when hibernation is not
            # in use, so this one can genuinely complete live.
            & powercfg.exe /hibernate off 2>&1 | Out-Null

            $hiberPath = Join-Path $Context.Root 'hiberfil.sys'
            if (-not (Test-Path -LiteralPath $hiberPath)) {
                $removed++
                Write-OperationLog -Message 'Hibernation disabled and hiberfil.sys removed.' -LogLevel 'INFO'
            }
            else {
                $warnings.Add('hiberfil.sys is still present after disabling hibernation. It will be removed on the next boot.')
            }
        }
        catch {
            $warnings.Add("Could not disable hibernation: $($_.Exception.Message)")
        }

        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if ($cs.AutomaticManagedPagefile) {
                Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $false } -ErrorAction Stop
                Write-OperationLog -Message 'Automatic pagefile management disabled.' -LogLevel 'INFO'
            }

            Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-CimInstance -InputObject $_ -ErrorAction SilentlyContinue
            }
        }
        catch {
            $warnings.Add("Could not deconfigure the pagefile: $($_.Exception.Message)")
        }

        try {
            $memoryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            Set-ItemProperty -LiteralPath $memoryKey -Name 'ClearPageFileAtShutdown' -Value 1 -Type DWord -ErrorAction Stop
            Write-OperationLog -Message 'ClearPageFileAtShutdown enabled. The pagefile is zeroed on the next clean shutdown.' -LogLevel 'INFO'
        }
        catch {
            $success = $false
            $warnings.Add("Could not set ClearPageFileAtShutdown: $($_.Exception.Message)")
        }

        $warnings.Add('Live mode cannot delete pagefile.sys while Windows is running. It is deconfigured and scheduled for zeroing, and a clean shutdown is REQUIRED before this machine is handed over. Run the wipe from the WinPE media to remove it outright.')
    }

    [PSCustomObject]@{
        Name          = 'PageAndHibernation'
        Success       = $success
        ItemsRemoved  = $removed
        PendingReboot = $pendingReboot
        Warnings      = $warnings.ToArray()
        Message       = "Removed $removed memory image file(s)." + $(if ($pendingReboot) { ' A clean shutdown is required to complete pagefile clearing.' } else { '' })
    }
}

function Clear-CredentialRemnant {
    <#
    .SYNOPSIS
        Destroys cached credentials and secrets belonging to previous users of the device.

    .DESCRIPTION
        This is the step that answers the actual requirement: the person keeps their AD
        account and uses it on a different machine, and nothing about that account is left
        behind on this one.

        Deleting a profile is not sufficient, because credential material for a domain user
        is also held outside the profile:

            - Cached domain logon verifiers, in HKLM\SECURITY\Cache as NL$1 through NL$10.
              These are the MSCACHEv2 verifiers that let a domain user log on to the
              machine with no domain controller reachable. They are derived from the
              account password and are offline-crackable. They are the single most
              sensitive per-user remnant on a domain-joined device.
            - NL$KM, in HKLM\SECURITY\Policy\Secrets, the key that encrypts that cache.
              Removed as well, so that any verifier this function fails to reach is
              cryptographically useless rather than merely deleted.
            - The machine-wide Credential Manager vault, which holds saved credentials for
              network resources, and is not inside any user profile.
            - Windows Hello and PIN containers under the NGC store.

        Two things are deliberately left alone, and the reasoning matters because both look
        like obvious targets:

        The machine DPAPI key (DPAPI_SYSTEM) and the machine key store under
        ProgramData\Microsoft\Crypto are NOT touched. They are machine credentials, not
        user data, and destroying them breaks certificate-based authentication, EFS and in
        some cases activation on the very OS install this wipe is preserving. Removing
        them would trade a real working machine for no privacy gain.

        A note on privilege. HKLM\SECURITY denies read access even to Administrators; only
        SYSTEM can open it. Live mode therefore attempts the SECURITY work, detects the
        access denial, and reports it honestly as a remnant it could not remove. Offline
        mode mounts the hive as a file and has no such problem. This is one of the clearest
        cases where the WinPE path removes something the live path structurally cannot.

    .PARAMETER Context
        Target context from Get-TargetContext.

    .OUTPUTS
        PSCustomObject: Name, Success, ItemsRemoved, Unreachable, Warnings, Message

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $warnings    = [System.Collections.Generic.List[string]]::new()
    $unreachable = [System.Collections.Generic.List[string]]::new()
    $removed     = 0
    $success     = $true

    if (-not $PSCmdlet.ShouldProcess($Context.Root, 'Destroy cached credentials and secrets')) {
        return [PSCustomObject]@{
            Name = 'CredentialRemnants'; Success = $true; ItemsRemoved = 0
            Unreachable = @(); Warnings = @(); Message = 'Declined at confirmation prompt.'
        }
    }

    # ---- 1. Cached domain logon verifiers and their encryption key --------
    $securityWork = Invoke-WithRegistryHive -Context $Context -Hive SECURITY -ScriptBlock {
        param($root)

        $cleared = 0

        # NL$1..NL$10 are the cached verifiers themselves.
        $cacheKey = Join-Path $root 'Cache'
        if (Test-Path -LiteralPath $cacheKey) {
            $props = Get-ItemProperty -LiteralPath $cacheKey -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties |
                    Where-Object { $_.Name -match '^NL\$\d+$' } |
                    ForEach-Object {
                        Remove-ItemProperty -LiteralPath $cacheKey -Name $_.Name -Force -ErrorAction SilentlyContinue
                        $cleared++
                    }
            }
        }

        # NL$KM decrypts the cache. Removing it makes any verifier that survived
        # unusable rather than merely deleted.
        $nlkmKey = Join-Path $root 'Policy\Secrets\NL$KM'
        if (Test-Path -LiteralPath $nlkmKey) {
            Remove-Item -LiteralPath $nlkmKey -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path -LiteralPath $nlkmKey)) { $cleared++ }
        }

        $cleared
    }

    if ($securityWork.Success) {
        $removed += [int]$securityWork.Result
        Write-OperationLog -Message "Cleared $($securityWork.Result) cached domain credential artifact(s)." -LogLevel 'SUCCESS'
    }
    else {
        # In live mode this is the expected outcome for a non-SYSTEM process, and it is
        # a real remnant, so it is reported rather than swallowed.
        $success = $false
        $unreachable.Add('HKLM\SECURITY cached domain logon verifiers (NL$1..NL$10, NL$KM)')

        if ($Context.IsOffline) {
            $warnings.Add("Could not clear cached domain credentials from the offline SECURITY hive: $($securityWork.Message)")
        }
        else {
            $warnings.Add('Cached domain logon verifiers could not be reached. HKLM\SECURITY is readable only by SYSTEM, and this process is not SYSTEM. The previous user''s offline-crackable credential cache is still on this device. Run the wipe from the WinPE media, or re-run this step as SYSTEM.')
        }
    }

    # ---- 2. Disable future credential caching ------------------------------
    $winlogon = Invoke-WithRegistryHive -Context $Context -Hive SOFTWARE -ScriptBlock {
        param($root)

        $key = Join-Path $root 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        if (Test-Path -LiteralPath $key) {
            # A string value, not a DWORD. Windows reads this one as text.
            Set-ItemProperty -LiteralPath $key -Name 'CachedLogonsCount' -Value '0' -Type String -ErrorAction SilentlyContinue

            # Clear the last signed-in user so the logon screen does not name the
            # previous owner of the device.
            foreach ($name in @('DefaultUserName', 'DefaultDomainName', 'LastUsedUsername', 'AltDefaultUserName', 'AltDefaultDomainName')) {
                Remove-ItemProperty -LiteralPath $key -Name $name -Force -ErrorAction SilentlyContinue
            }

            return $true
        }

        $false
    }

    if ($winlogon.Success -and $winlogon.Result) {
        $removed++
        Write-OperationLog -Message 'Credential caching disabled and the last signed-in user cleared.' -LogLevel 'INFO'
    }
    else {
        $warnings.Add("Could not update Winlogon credential settings: $($winlogon.Message)")
    }

    # ---- 3. Machine-wide credential and secret stores on disk --------------
    $credentialPaths = @(
        (Join-Path $Context.ProgramDataDir 'Microsoft\Vault'),
        (Join-Path $Context.WindowsDir 'System32\config\systemprofile\AppData\Roaming\Microsoft\Credentials'),
        (Join-Path $Context.WindowsDir 'System32\config\systemprofile\AppData\Local\Microsoft\Credentials'),
        (Join-Path $Context.WindowsDir 'ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc'),
        (Join-Path $Context.WindowsDir 'ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Credentials')
    )

    foreach ($path in $credentialPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        try {
            if (-not $Context.IsOffline) {
                & takeown.exe /f "$path" /r /d y 2>&1 | Out-Null
                & icacls.exe "$path" /grant administrators:F /t /c /q 2>&1 | Out-Null
            }

            $children = @(Get-ChildItem -LiteralPath $path -Force -Recurse -ErrorAction SilentlyContinue)
            Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

            $removed += $children.Count
            Write-OperationLog -Message "Cleared credential store: $path ($($children.Count) item(s))" -LogLevel 'INFO'
        }
        catch {
            $warnings.Add("Could not fully clear '$path': $($_.Exception.Message)")
        }
    }

    # ---- 4. Credential Manager, live only ----------------------------------
    # cmdkey operates on the calling user's vault, so it can only ever clean the
    # operator's own saved credentials. Other users' vaults live in their profiles and
    # are removed with them.
    if (-not $Context.IsOffline) {
        try {
            $stored = @(& cmdkey.exe /list 2>&1 | Select-String -Pattern 'Target:\s*(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })

            foreach ($target in $stored) {
                & cmdkey.exe /delete:$target 2>&1 | Out-Null
                $removed++
            }

            if ($stored.Count -gt 0) {
                Write-OperationLog -Message "Removed $($stored.Count) saved credential(s) from the operator's Credential Manager." -LogLevel 'INFO'
            }
        }
        catch {
            $warnings.Add("Could not enumerate Credential Manager entries: $($_.Exception.Message)")
        }
    }

    [PSCustomObject]@{
        Name         = 'CredentialRemnants'
        Success      = $success
        ItemsRemoved = $removed
        Unreachable  = $unreachable.ToArray()
        Warnings     = $warnings.ToArray()
        Message      = "Removed $removed credential artifact(s)." + $(if ($unreachable.Count) { " $($unreachable.Count) store(s) could not be reached." } else { '' })
    }
}

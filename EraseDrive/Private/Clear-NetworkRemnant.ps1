function Clear-NetworkRemnant {
    <#
    .SYNOPSIS
        Removes evidence of the networks the device was attached to.

    .DESCRIPTION
        This is the part of "remove it from the LAN" that survives a domain unjoin, and it
        is the part people forget. Unjoining the domain does not remove any of the
        following, all of which name the company out loud on a device that is about to
        belong to somebody else:

            - Saved wireless profiles, including the SSID and, for WPA2-PSK networks, the
              stored key. On a corporate 802.1X network the profile also names the RADIUS
              server and the trusted root CA.
            - The NetworkList registry records: every network the machine has ever joined,
              by name, with first and last connection timestamps, and for domain networks
              the DNS suffix of the company.
            - VPN phonebook entries naming the gateway.
            - Network printer connections naming print servers.
            - Static proxy settings naming internal infrastructure.
            - Any hosts file entries pointing at internal addresses.

        Mapped network drives are deliberately not handled here. They live in each user's
        own HKCU\Network key and go with the profile, so handling them separately would be
        duplicate work that could only disagree with itself.

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

    if (-not $PSCmdlet.ShouldProcess($Context.Root, 'Remove wireless profiles, network history, VPN and proxy settings')) {
        return [PSCustomObject]@{
            Name = 'NetworkRemnants'; Success = $true; ItemsRemoved = 0
            Warnings = @(); Message = 'Declined at confirmation prompt.'
        }
    }

    # ---- 1. Wireless profiles ---------------------------------------------
    if (-not $Context.IsOffline) {
        try {
            $profileOutput = & netsh.exe wlan show profiles 2>&1
            $profileNames  = @($profileOutput | Select-String -Pattern ':\s*(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | Where-Object { $_ })

            foreach ($name in $profileNames) {
                & netsh.exe wlan delete profile name="$name" 2>&1 | Out-Null
                $removed++
            }

            if ($profileNames.Count -gt 0) {
                Write-OperationLog -Message "Deleted $($profileNames.Count) wireless profile(s)." -LogLevel 'INFO'
            }
        }
        catch {
            # A machine with no wireless adapter makes netsh return an error. Not a failure.
            Write-OperationLog -Message "No wireless profiles removed: $($_.Exception.Message)" -LogLevel 'INFO'
        }
    }

    # The on-disk profile XMLs are the authoritative store and are removed in both modes.
    # In live mode netsh should already have cleared them; anything left here is a profile
    # netsh did not enumerate, which is exactly what must not be left behind.
    $wlanProfileDir = Join-Path $Context.ProgramDataDir 'Microsoft\Wlansvc\Profiles\Interfaces'
    if (Test-Path -LiteralPath $wlanProfileDir) {
        try {
            $xmlFiles = @(Get-ChildItem -LiteralPath $wlanProfileDir -Filter '*.xml' -Recurse -Force -ErrorAction SilentlyContinue)
            foreach ($xml in $xmlFiles) {
                Remove-Item -LiteralPath $xml.FullName -Force -ErrorAction SilentlyContinue
                $removed++
            }
            if ($xmlFiles.Count -gt 0) {
                Write-OperationLog -Message "Removed $($xmlFiles.Count) wireless profile file(s) from disk." -LogLevel 'INFO'
            }
        }
        catch {
            $warnings.Add("Could not clear wireless profile files: $($_.Exception.Message)")
        }
    }

    # ---- 2. VPN phonebooks -------------------------------------------------
    $pbkPath = Join-Path $Context.ProgramDataDir 'Microsoft\Network\Connections\Pbk'
    if (Test-Path -LiteralPath $pbkPath) {
        try {
            Get-ChildItem -LiteralPath $pbkPath -Filter '*.pbk' -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
                $removed++
            }
            Write-OperationLog -Message 'Removed all-user VPN phonebook entries.' -LogLevel 'INFO'
        }
        catch {
            $warnings.Add("Could not clear VPN phonebooks: $($_.Exception.Message)")
        }
    }

    # ---- 3. Network printers, live only ------------------------------------
    if (-not $Context.IsOffline) {
        try {
            Get-Printer -ErrorAction SilentlyContinue |
                Where-Object { $_.Type -eq 'Connection' -or $_.PortName -match '^\\\\' } |
                ForEach-Object {
                    try {
                        Remove-Printer -Name $_.Name -ErrorAction Stop
                        $removed++
                        Write-OperationLog -Message "Removed network printer: $($_.Name)" -LogLevel 'INFO'
                    }
                    catch {
                        $warnings.Add("Could not remove printer '$($_.Name)': $($_.Exception.Message)")
                    }
                }
        }
        catch {
            $warnings.Add("Could not enumerate printers: $($_.Exception.Message)")
        }

        try {
            & netsh.exe winhttp reset proxy 2>&1 | Out-Null
            Write-OperationLog -Message 'WinHTTP proxy configuration reset.' -LogLevel 'INFO'
        }
        catch {
            $warnings.Add("Could not reset the WinHTTP proxy: $($_.Exception.Message)")
        }
    }

    # ---- 4. Hosts file -----------------------------------------------------
    # Reset to the stock Windows content rather than deleting: an absent hosts file
    # is itself unusual and some software objects to it.
    $hostsPath = Join-Path $Context.WindowsDir 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsPath) {
        try {
            $existing = @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue |
                            Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith('#') })

            if ($existing.Count -gt 0) {
                $default = @(
                    '# Copyright (c) 1993-2009 Microsoft Corp.',
                    '#',
                    '# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.',
                    '#',
                    '# This file contains the mappings of IP addresses to host names. Each',
                    '# entry should be kept on an individual line. The IP address should',
                    '# be placed in the first column followed by the corresponding host name.',
                    '#',
                    '#	127.0.0.1       localhost',
                    '#	::1             localhost'
                )

                Set-Content -LiteralPath $hostsPath -Value $default -Force -ErrorAction Stop
                $removed += $existing.Count
                Write-OperationLog -Message "Reset the hosts file, removing $($existing.Count) active entry/entries." -LogLevel 'INFO'
            }
        }
        catch {
            $warnings.Add("Could not reset the hosts file: $($_.Exception.Message)")
        }
    }

    # ---- 5. Network history in the registry --------------------------------
    # NetworkList is the record of every network this machine has joined, by name.
    $netList = Invoke-WithRegistryHive -Context $Context -Hive SOFTWARE -ScriptBlock {
        param($root)

        $count = 0
        $targets = @(
            'Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles',
            'Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged',
            'Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed',
            'Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache'
        )

        foreach ($relative in $targets) {
            $key = Join-Path $root $relative
            if (Test-Path -LiteralPath $key) {
                Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-Item -LiteralPath $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    $count++
                }
            }
        }

        $count
    }

    if ($netList.Success) {
        $removed += [int]$netList.Result
        Write-OperationLog -Message "Removed $($netList.Result) network history record(s) from the registry." -LogLevel 'INFO'
    }
    else {
        $success = $false
        $warnings.Add("Could not clear network history from the registry: $($netList.Message)")
    }

    [PSCustomObject]@{
        Name         = 'NetworkRemnants'
        Success      = $success
        ItemsRemoved = $removed
        Warnings     = $warnings.ToArray()
        Message      = "Removed $removed network remnant(s)."
    }
}

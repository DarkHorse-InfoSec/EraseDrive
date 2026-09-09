function Remove-DomainMembership {
    <#
    .SYNOPSIS
        Removes the device from its Active Directory domain without making any change to Active Directory.

    .DESCRIPTION
        The requirement this implements, in the words it was given in: the departing user
        keeps their AD account so they can sign in on another device, and this device keeps
        nothing about them. So the device leaves the domain and the directory is not
        touched.

        THE NO-DIRECTORY-WRITE INVARIANT

        This function accepts no credential. There is deliberately no -Credential,
        -UnjoinDomainCredential or PSCredential parameter of any kind, and none is
        constructed internally. That is not a stylistic choice, it is the enforcement
        mechanism: a domain unjoin can only disable or delete the computer account in AD
        if it authenticates to a domain controller, and it can only authenticate with a
        credential. With no credential anywhere in the call path, the unjoin is local by
        construction rather than by intention, and no amount of misuse by a caller can
        turn it into a directory write.

        Win32_ComputerSystem.UnjoinDomainOrWorkgroup is called directly with
        FUnjoinOptions = 0 rather than using Remove-Computer, for the same reason.
        Remove-Computer will contact a domain controller with the caller's ambient
        Kerberos ticket, and its behaviour then depends on that user's rights in the
        directory. The explicit WMI call with no options and no credentials does not.

        The computer object is therefore left in AD, exactly as it was, for the normal
        stale-object cleanup process to handle.

        What is removed locally:
            - Domain membership itself; the machine is placed in a workgroup.
            - The machine account secret, so the device cannot re-authenticate.
            - The recorded domain name and DNS suffix, which name the company.

        Offline mode does as much of this as can be done to a hive file and reports
        RequiresBootToComplete, because the final state transition is performed by the
        Netlogon service on the next boot. An offline unjoin that claimed to be complete
        would be overclaiming.

    .PARAMETER Context
        Target context from Get-TargetContext.

    .PARAMETER WorkgroupName
        Workgroup to place the machine in. Defaults to WORKGROUP.

    .OUTPUTS
        PSCustomObject: Name, Success, WasDomainJoined, PreviousDomain,
                        RequiresBootToComplete, Warnings, Message

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context,

        [Parameter()]
        [ValidatePattern('^[A-Za-z0-9\-]{1,15}$')]
        [string]$WorkgroupName = 'WORKGROUP'
    )

    $warnings        = [System.Collections.Generic.List[string]]::new()
    $success         = $true
    $wasJoined       = $false
    $previousDomain  = $null
    $requiresBoot    = $false

    # ---- 1. Establish current membership -----------------------------------
    if ($Context.IsOffline) {
        $probe = Invoke-WithRegistryHive -Context $Context -Hive SYSTEM -ScriptBlock {
            param($root)

            $controlSet = Get-ControlSetPath -HiveRoot $root -IsOffline $true
            if (-not $controlSet) { return $null }

            $tcpip = Join-Path $controlSet 'Services\Tcpip\Parameters'
            if (Test-Path -LiteralPath $tcpip) {
                $props = Get-ItemProperty -LiteralPath $tcpip -ErrorAction SilentlyContinue
                return $props.'NV Domain'
            }

            $null
        }

        $previousDomain = $probe.Result
        $wasJoined = -not [string]::IsNullOrWhiteSpace($previousDomain)
    }
    else {
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $wasJoined = [bool]$cs.PartOfDomain
            $previousDomain = $(if ($wasJoined) { $cs.Domain } else { $null })
        }
        catch {
            $success = $false
            $warnings.Add("Could not determine domain membership: $($_.Exception.Message)")
        }
    }

    if (-not $wasJoined) {
        Write-OperationLog -Message 'Device is not domain joined; nothing to unjoin.' -LogLevel 'INFO'
        return [PSCustomObject]@{
            Name = 'DomainMembership'; Success = $true; WasDomainJoined = $false
            PreviousDomain = $null; RequiresBootToComplete = $false
            Warnings = @(); Message = 'Device was not domain joined.'
        }
    }

    if (-not $PSCmdlet.ShouldProcess("$($Context.Root) (domain: $previousDomain)", "Remove from domain, place in workgroup '$WorkgroupName'. No Active Directory objects are modified.")) {
        return [PSCustomObject]@{
            Name = 'DomainMembership'; Success = $true; WasDomainJoined = $true
            PreviousDomain = $previousDomain; RequiresBootToComplete = $false
            Warnings = @(); Message = 'Declined at confirmation prompt.'
        }
    }

    Write-OperationLog -Message "Removing device from domain '$previousDomain'. No Active Directory objects will be modified." -LogLevel 'INFO'

    # ---- 2. Perform the unjoin ---------------------------------------------
    if (-not $Context.IsOffline) {
        try {
            # FUnjoinOptions = 0 means: do not touch the computer account in the
            # directory. UserName and Password are omitted entirely, so there is no
            # authenticated session in which a directory change could occur.
            $unjoin = Invoke-CimMethod -ClassName Win32_ComputerSystem `
                -MethodName 'UnjoinDomainOrWorkgroup' `
                -Arguments @{ FUnjoinOptions = [uint32]0 } `
                -ErrorAction Stop

            if ($unjoin.ReturnValue -ne 0) {
                $success = $false
                $warnings.Add("Local unjoin returned code $($unjoin.ReturnValue).")
            }
            else {
                Write-OperationLog -Message 'Local domain unjoin succeeded.' -LogLevel 'SUCCESS'
            }

            # FJoinOptions = 0 joins a workgroup rather than a domain.
            $join = Invoke-CimMethod -ClassName Win32_ComputerSystem `
                -MethodName 'JoinDomainOrWorkgroup' `
                -Arguments @{ Name = $WorkgroupName; FJoinOptions = [uint32]0 } `
                -ErrorAction Stop

            if ($join.ReturnValue -ne 0) {
                $success = $false
                $warnings.Add("Workgroup join returned code $($join.ReturnValue).")
            }

            $requiresBoot = $true
        }
        catch {
            $success = $false
            $warnings.Add("Domain unjoin failed: $($_.Exception.Message)")
        }
    }
    else {
        # Offline: clear the recorded membership so the next boot does not present the
        # device as a domain member.
        $clear = Invoke-WithRegistryHive -Context $Context -Hive SYSTEM -ScriptBlock {
            param($root)

            $controlSet = Get-ControlSetPath -HiveRoot $root -IsOffline $true
            if (-not $controlSet) { return $false }

            $tcpip = Join-Path $controlSet 'Services\Tcpip\Parameters'
            if (Test-Path -LiteralPath $tcpip) {
                foreach ($name in @('Domain', 'NV Domain', 'DhcpDomain')) {
                    Set-ItemProperty -LiteralPath $tcpip -Name $name -Value '' -Type String -ErrorAction SilentlyContinue
                }
            }

            # Netlogon caches the domain it last authenticated against.
            $netlogon = Join-Path $controlSet 'Services\Netlogon\Parameters'
            if (Test-Path -LiteralPath $netlogon) {
                Remove-ItemProperty -LiteralPath $netlogon -Name 'SiteName' -Force -ErrorAction SilentlyContinue
            }

            $true
        }

        if (-not $clear.Success -or -not $clear.Result) {
            $success = $false
            $warnings.Add("Could not clear offline domain membership records: $($clear.Message)")
        }

        # The machine account secret is what lets the device re-authenticate to the
        # domain. Removing it means the device cannot rejoin silently even if a
        # membership record were missed.
        $secret = Invoke-WithRegistryHive -Context $Context -Hive SECURITY -ScriptBlock {
            param($root)

            $key = Join-Path $root 'Policy\Secrets\$MACHINE.ACC'
            if (Test-Path -LiteralPath $key) {
                Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
                return (-not (Test-Path -LiteralPath $key))
            }

            $true
        }

        if (-not $secret.Success) {
            $warnings.Add("Could not remove the machine account secret from the offline SECURITY hive: $($secret.Message)")
        }
        else {
            Write-OperationLog -Message 'Machine account secret removed. The device cannot re-authenticate to the domain.' -LogLevel 'SUCCESS'
        }

        $requiresBoot = $true
        $warnings.Add('Offline unjoin clears the recorded membership and the machine account secret. Windows completes the transition to workgroup state on the next boot; boot the machine once and confirm before handing it over.')
    }

    [PSCustomObject]@{
        Name                   = 'DomainMembership'
        Success                = $success
        WasDomainJoined        = $true
        PreviousDomain         = $previousDomain
        RequiresBootToComplete = $requiresBoot
        Warnings               = $warnings.ToArray()
        Message                = "Removed from domain '$previousDomain'. No Active Directory objects were modified; the computer object remains for normal directory cleanup."
    }
}

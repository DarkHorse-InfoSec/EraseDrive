function Get-ControlSetPath {
    <#
    .SYNOPSIS
        Resolves the active control set path inside a live or offline SYSTEM hive.

    .DESCRIPTION
        A running system exposes the active control set as the symbolic link
        HKLM\SYSTEM\CurrentControlSet. That link does not exist in an unmounted SYSTEM
        hive: a mounted hive contains ControlSet001, usually ControlSet002, and a Select
        key whose Current value says which one the system actually boots from.

        Writing to the wrong control set offline is a silent failure. The write succeeds,
        the value is visibly present when inspected, and the setting has no effect on the
        next boot because that control set is not the one being used. Every offline
        registry change in this module goes through here for that reason.

    .PARAMETER HiveRoot
        The hive root handed to a scriptblock by Invoke-WithRegistryHive. For live mode
        this is 'HKLM:\SYSTEM'; for offline it is the temporary mount path.

    .PARAMETER IsOffline
        Whether the hive is an offline mount.

    .OUTPUTS
        [string] Full registry path to the active control set, or $null when it cannot be
        determined offline.

    .EXAMPLE
        Invoke-WithRegistryHive -Context $ctx -Hive SYSTEM -ScriptBlock {
            param($root)
            $cs = Get-ControlSetPath -HiveRoot $root -IsOffline $ctx.IsOffline
            Set-ItemProperty "$cs\Control\Session Manager\Memory Management" -Name ClearPageFileAtShutdown -Value 1
        }

    .NOTES
        Private helper. Module: EraseDrive
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$HiveRoot,

        [Parameter(Mandatory)]
        [bool]$IsOffline
    )

    if (-not $IsOffline) {
        return "$HiveRoot\CurrentControlSet"
    }

    # Select\Current names the control set the system boots from, as a DWORD: 1 means
    # ControlSet001.
    $selectKey = Join-Path $HiveRoot 'Select'

    if (Test-Path -LiteralPath $selectKey) {
        $current = (Get-ItemProperty -LiteralPath $selectKey -Name 'Current' -ErrorAction SilentlyContinue).Current

        if ($null -ne $current) {
            $candidate = Join-Path $HiveRoot ('ControlSet{0:D3}' -f [int]$current)
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }

            Write-OperationLog -Message "Select\Current names ControlSet$('{0:D3}' -f [int]$current) but that key is absent from the hive." -LogLevel 'WARNING'
        }
    }

    # Fall back to the only control set present, but only when there is exactly one.
    # Guessing between two is how the wrong one gets written to.
    $sets = @(Get-ChildItem -LiteralPath $HiveRoot -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^ControlSet\d{3}$' })

    if ($sets.Count -eq 1) {
        Write-OperationLog -Message "Select key unreadable; using the only control set present ($($sets[0].PSChildName))." -LogLevel 'WARNING'
        return $sets[0].PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE', 'HKLM:'
    }

    Write-OperationLog -Message "Could not determine the active control set: Select key unreadable and $($sets.Count) control sets present. Offline registry changes to the control set will be skipped rather than written to a guess." -LogLevel 'ERROR'
    return $null
}

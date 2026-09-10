#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

<#
.SYNOPSIS
    Tests for the guards that decide a disk must not be erased.

.DESCRIPTION
    `Test-DiskSafeToErase` is the last thing standing between an operator and the
    wrong disk, so each refusal is asserted BY ITS REASON. Asserting only that a
    guard refused lets a dead guard look tested, which this repo has already been
    bitten by: the Storage Space / RAID check passed for months while throwing a
    parameter-transformation error and never reaching the check it claimed to make.

    The self-erase guard added on 2026-09-09 closes a gap none of the other checks
    covered. EraseDrive is designed to run from removable media, and a USB stick
    carrying the tool is not the system disk, is not the boot disk, is healthy, has
    no \\Windows on it, and (unlike a Windows-installed drive) has no reserved or
    recovery partition to trip the partition-type check. Every existing test passes
    it as safe. Erasing it would destroy the running code mid-operation.

.NOTES
    Run with:  Invoke-Pester -Path .\Tests\SafetyGuards.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:repoRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $script:modulePath = Join-Path $script:repoRoot 'EraseDrive'

    $Script:EraseDriveConfig = @{
        LogDirectory  = Join-Path $TestDrive 'Logs'
        LogFile       = Join-Path (Join-Path $TestDrive 'Logs') 'EraseDrive.log'
        CertDirectory = Join-Path $TestDrive 'Certs'
        MaxLogSizeMB  = 1
        MaxLogFiles   = 3
        Version       = '3.1.0'
        ModuleRoot    = $script:modulePath
    }
    New-Item -Path $Script:EraseDriveConfig.LogDirectory -ItemType Directory -Force | Out-Null
    New-Item -Path $Script:EraseDriveConfig.CertDirectory -ItemType Directory -Force | Out-Null

    Get-ChildItem (Join-Path $script:modulePath 'Private') -Filter '*.ps1' | ForEach-Object { . $_.FullName }
}

Describe 'Test-DiskSafeToErase: the self-erase guard' {

    BeforeAll { Mock Write-OperationLog { } }

    BeforeEach {
        # A plain removable stick: online, healthy, not system, not boot, one basic
        # data partition, no reserved or recovery partition. This is the intended
        # deployment medium for EraseDrive, and every pre-existing check passes it.
        Mock Get-Disk {
            [PSCustomObject]@{
                Number            = 7
                Size              = 114GB
                IsSystem          = $false
                IsBoot            = $false
                HealthStatus      = 'Healthy'
                OperationalStatus = 'Online'
            }
        }
        Mock Get-VirtualDisk { @() }
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage', 'HealthStatus', 'VirtualDisk' {
            @([PSCustomObject]@{ DeviceId = '7'; BusType = 'USB'; FriendlyName = 'Stick' })
        }

        # The partitions ON the disk: one basic volume, no drive letter, so the
        # \Windows and \Program Files probes are not what does the refusing here.
        Mock Get-Partition -ParameterFilter { $null -ne $DiskNumber } {
            @([PSCustomObject]@{ DiskNumber = 7; PartitionNumber = 1; Type = 'Basic'; DriveLetter = $null })
        }
    }

    It 'refuses a disk that holds the EraseDrive module itself' {
        # Resolving the module's own drive letter lands on the disk being erased.
        Mock Get-Partition -ParameterFilter { $null -ne $DriveLetter } {
            [PSCustomObject]@{ DiskNumber = 7; PartitionNumber = 1; DriveLetter = $DriveLetter }
        }

        $result = Test-DiskSafeToErase -DiskNumber 7

        $result.Safe   | Should -BeFalse
        $result.Reason | Should -Match 'EraseDrive itself|current working directory'
        $result.Reason | Should -Match 'disk 7'
    }

    It 'allows a disk that holds nothing of ours' {
        # The other side of the guard. A check that always refuses would pass the
        # test above and be useless; this is what proves it discriminates.
        Mock Get-Partition -ParameterFilter { $null -ne $DriveLetter } {
            [PSCustomObject]@{ DiskNumber = 3; PartitionNumber = 1; DriveLetter = $DriveLetter }
        }

        $result = Test-DiskSafeToErase -DiskNumber 7

        $result.Safe   | Should -BeTrue
        $result.Reason | Should -Match 'safe to erase'
    }

    It 'reports an undetermined self-check instead of silently passing it' {
        # If our own volume cannot be resolved to a disk we do not know whether the
        # target is ours. That uncertainty is surfaced in the reason rather than
        # being treated as a clean bill of health.
        Mock Get-Partition -ParameterFilter { $null -ne $DriveLetter } { throw 'no such volume' }

        $result = Test-DiskSafeToErase -DiskNumber 7

        $result.Safe   | Should -BeTrue
        $result.Reason | Should -Match 'could not determine which disk holds EraseDrive'
    }
}

Describe 'Test-DiskSafeToErase: the pre-existing refusals still fire, and say why' {

    BeforeAll { Mock Write-OperationLog { } }

    BeforeEach {
        Mock Get-VirtualDisk { @() }
        Mock Get-PhysicalDisk -RemoveParameterType 'Usage', 'HealthStatus', 'VirtualDisk' {
            @([PSCustomObject]@{ DeviceId = '7'; BusType = 'USB'; FriendlyName = 'Stick' })
        }
        Mock Get-Partition { @() }
    }

    It 'refuses an offline disk' {
        Mock Get-Disk {
            [PSCustomObject]@{ Number = 7; Size = 1GB; IsSystem = $false; IsBoot = $false
                               HealthStatus = 'Healthy'; OperationalStatus = 'Offline' }
        }
        $r = Test-DiskSafeToErase -DiskNumber 7
        $r.Safe | Should -BeFalse
        $r.Reason | Should -Match 'offline'
    }

    It 'refuses the system disk' {
        Mock Get-Disk {
            [PSCustomObject]@{ Number = 7; Size = 1GB; IsSystem = $true; IsBoot = $false
                               HealthStatus = 'Healthy'; OperationalStatus = 'Online' }
        }
        $r = Test-DiskSafeToErase -DiskNumber 7
        $r.Safe | Should -BeFalse
        $r.Reason | Should -Match 'system disk'
    }

    It 'refuses the boot disk' {
        Mock Get-Disk {
            [PSCustomObject]@{ Number = 7; Size = 1GB; IsSystem = $false; IsBoot = $true
                               HealthStatus = 'Healthy'; OperationalStatus = 'Online' }
        }
        $r = Test-DiskSafeToErase -DiskNumber 7
        $r.Safe | Should -BeFalse
        $r.Reason | Should -Match 'boot disk'
    }

    It 'refuses an unhealthy disk and names the status' {
        Mock Get-Disk {
            [PSCustomObject]@{ Number = 7; Size = 1GB; IsSystem = $false; IsBoot = $false
                               HealthStatus = 'Warning'; OperationalStatus = 'Online' }
        }
        $r = Test-DiskSafeToErase -DiskNumber 7
        $r.Safe | Should -BeFalse
        $r.Reason | Should -Match 'Warning'
    }

    It 'refuses a disk carrying a system, reserved or recovery partition' -ForEach @(
        @{ PType = 'System' }
        @{ PType = 'Reserved' }
        @{ PType = 'Recovery' }
    ) {
        # This is what actually protects a Windows-installed secondary drive, and
        # it is why the self-erase guard was needed separately: a plain data stick
        # has none of these partition types.
        Mock Get-Disk {
            [PSCustomObject]@{ Number = 7; Size = 1GB; IsSystem = $false; IsBoot = $false
                               HealthStatus = 'Healthy'; OperationalStatus = 'Online' }
        }
        Mock Get-Partition -ParameterFilter { $null -ne $DiskNumber } {
            @([PSCustomObject]@{ DiskNumber = 7; PartitionNumber = 1; Type = $PType; DriveLetter = $null })
        }

        $r = Test-DiskSafeToErase -DiskNumber 7
        $r.Safe | Should -BeFalse
        $r.Reason | Should -Match 'system, reserved, or recovery'
    }

    It 'reports an error accessing the disk as unsafe, not as safe' {
        Mock Get-Disk { throw 'The device is not ready.' }
        $r = Test-DiskSafeToErase -DiskNumber 7
        $r.Safe | Should -BeFalse
        $r.Reason | Should -Match 'Error accessing disk'
    }
}

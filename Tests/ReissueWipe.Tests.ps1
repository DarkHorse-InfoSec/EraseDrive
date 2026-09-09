#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

<#
.SYNOPSIS
    Pester 5.x tests for the device reissue and resale wipe.

.DESCRIPTION
    Covers the functions added for whole-device reissue, plus regression tests for the two
    defects found in Invoke-ForensicUserDataWipe.

    These tests assert invariants over a cross-product of inputs rather than over one
    illustrative case. A test that exercises only the path the code already handles buys
    confidence it has not earned, and for anything guarding data destruction that is worse
    than no test at all.

    Runtime behaviour of the destructive primitives is NOT covered here and cannot be:
    verifying that a wipe actually wipes requires a disposable machine. These tests cover
    selection, refusal, ordering and reporting, which is where the defects were.

.NOTES
    Run with:  Invoke-Pester -Path .\Tests\ReissueWipe.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $script:modulePath = Join-Path (Join-Path $PSScriptRoot '..') 'EraseDrive'

    $Script:EraseDriveConfig = @{
        LogDirectory  = Join-Path $TestDrive 'Logs'
        LogFile       = Join-Path (Join-Path $TestDrive 'Logs') 'EraseDrive.log'
        CertDirectory = Join-Path $TestDrive 'Certs'
        LicensePath   = Join-Path $TestDrive 'license.lic'
        PublicKeyPath = Join-Path $TestDrive 'no-such-key.xml'
        MaxLogSizeMB  = 1
        MaxLogFiles   = 3
        Version       = '3.1.0'
        ModuleRoot    = $script:modulePath
        EvidenceRoot  = $null
    }

    New-Item -Path $Script:EraseDriveConfig.LogDirectory -ItemType Directory -Force | Out-Null
    New-Item -Path $Script:EraseDriveConfig.CertDirectory -ItemType Directory -Force | Out-Null

    Get-ChildItem (Join-Path $script:modulePath 'Private') -Filter '*.ps1' | ForEach-Object { . $_.FullName }
    Get-ChildItem (Join-Path $script:modulePath 'Public') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

    # Builds a directory tree that looks enough like a Windows install for
    # Get-TargetContext to accept it.
    function New-FakeWindowsVolume {
        param([string]$Root)

        $config = Join-Path $Root 'Windows\System32\config'
        New-Item -Path $config -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $Root 'Users') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $Root 'ProgramData') -ItemType Directory -Force | Out-Null

        foreach ($hive in @('SOFTWARE', 'SYSTEM', 'SAM', 'SECURITY', 'DEFAULT')) {
            Set-Content -Path (Join-Path $config $hive) -Value 'fake hive' -Force
        }

        return $Root
    }
}

# ============================================================================
# Get-TargetContext
# ============================================================================
Describe 'Get-TargetContext' {

    Context 'Live mode' {
        It 'resolves the running installation as valid and not offline' {
            $ctx = Get-TargetContext
            $ctx.Valid     | Should -BeTrue
            $ctx.IsOffline | Should -BeFalse
        }

        It 'normalises the root to a trailing separator' {
            (Get-TargetContext).Root | Should -Match '\\$'
        }

        It 'derives every hive path from the config directory' {
            $ctx = Get-TargetContext
            foreach ($p in @($ctx.SoftwareHive, $ctx.SystemHive, $ctx.SamHive, $ctx.SecurityHive, $ctx.DefaultHive)) {
                $p | Should -Match 'System32\\config\\'
            }
        }
    }

    Context 'Offline mode with a valid volume' {
        BeforeAll {
            $script:fakeRoot = New-FakeWindowsVolume -Root (Join-Path $TestDrive 'FakeWin')
        }

        It 'accepts a directory tree that contains a hive set' {
            $ctx = Get-TargetContext -OfflineRoot $script:fakeRoot
            $ctx.Valid     | Should -BeTrue
            $ctx.IsOffline | Should -BeTrue
        }

        It 'rebases every derived path onto the offline root' {
            $ctx = Get-TargetContext -OfflineRoot $script:fakeRoot
            $ctx.WindowsDir     | Should -BeLike "$script:fakeRoot*"
            $ctx.UsersDir       | Should -BeLike "$script:fakeRoot*"
            $ctx.ProgramDataDir | Should -BeLike "$script:fakeRoot*"
        }
    }

    Context 'Offline mode rejections' {
        # The cross-product that matters: each way a root can be wrong must be refused,
        # and refused with a reason that names the actual problem.
        It 'refuses <Label>' -ForEach @(
            @{ Label = 'a path that does not exist';        Path = 'Q:\definitely-not-here' }
            @{ Label = 'a path with no Windows directory';  Path = $null }
        ) {
            $target = if ($Path) { $Path } else { (New-Item -Path (Join-Path $TestDrive "empty_$([guid]::NewGuid().ToString('N').Substring(0,6))") -ItemType Directory -Force).FullName }

            $ctx = Get-TargetContext -OfflineRoot $target
            $ctx.Valid  | Should -BeFalse
            $ctx.Reason | Should -Not -BeNullOrEmpty
        }

        It 'refuses a Windows directory with no registry hives' {
            $noHives = Join-Path $TestDrive 'NoHives'
            New-Item -Path (Join-Path $noHives 'Windows\System32\config') -ItemType Directory -Force | Out-Null

            $ctx = Get-TargetContext -OfflineRoot $noHives
            $ctx.Valid  | Should -BeFalse
            $ctx.Reason | Should -Match 'hives'
        }

        It 'refuses the currently running Windows installation, naming that as the reason' {
            # The safety guard. On first implementation this refusal happened for an
            # unrelated reason (an access-denied hive probe ran first), which made the
            # guard dead code that still looked tested. The reason is asserted, not just
            # the refusal.
            $ctx = Get-TargetContext -OfflineRoot "$($env:SystemDrive)\"
            $ctx.Valid  | Should -BeFalse
            $ctx.Reason | Should -Match 'currently running Windows installation'
        }

        It 'does not mistake an access-denied hive for a missing one' {
            # Regression: Test-Path throws on the live hive files when unelevated, and
            # treating that as absence rejected a perfectly good Windows install.
            $ctx = Get-TargetContext
            $ctx.Valid | Should -BeTrue -Because 'the live install has hives even when they cannot be stat-ed'
        }
    }
}

# ============================================================================
# Get-ProtectedSessionPrincipal - defect D1
# ============================================================================
Describe 'Get-ProtectedSessionPrincipal' {

    It 'protects nothing when the target is offline' {
        $ctx  = [PSCustomObject]@{ IsOffline = $true; Valid = $true; Root = 'C:\' }
        $prot = Get-ProtectedSessionPrincipal -Context $ctx

        $prot.IsEmpty    | Should -BeTrue
        $prot.Sids.Count | Should -Be 0
    }

    It 'protects the current operator when the target is live' {
        $prot       = Get-ProtectedSessionPrincipal -Context (Get-TargetContext)
        $currentSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

        $prot.Sids | Should -Contain $currentSid
    }

    It 'gives every protected principal a stated reason' {
        $prot = Get-ProtectedSessionPrincipal -Context (Get-TargetContext)
        foreach ($sid in $prot.Sids) {
            $prot.Reasons[$sid] | Should -Not -BeNullOrEmpty
        }
    }
}

# ============================================================================
# Remove-UserProfileData - defect D1 regression
# ============================================================================
Describe 'Remove-UserProfileData' {

    Context 'Protected accounts are never targeted' {
        BeforeAll {
            $script:protectedSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
            $script:targetSid    = 'S-1-5-21-1111111111-2222222222-3333333333-1002'

            $script:liveCtx = [PSCustomObject]@{
                IsOffline = $false; Valid = $true; Root = 'C:\'
                WindowsDir = 'C:\Windows'; UsersDir = 'C:\Users'
                Description = 'test live context'
            }

            $script:protected = [PSCustomObject]@{
                Sids    = @($script:protectedSid)
                Names   = @('operator')
                Reasons = @{ $script:protectedSid = 'Operator running this wipe.' }
                IsEmpty = $false
            }
        }

        It 'never reports a protected profile as removed' {
            Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_UserProfile' } -MockWith {
                @(
                    [PSCustomObject]@{ SID = $script:protectedSid; LocalPath = 'C:\Users\operator'; Special = $false }
                    [PSCustomObject]@{ SID = $script:targetSid;    LocalPath = 'C:\Users\departed'; Special = $false }
                )
            }
            Mock Get-Process { @() }
            Mock Test-Path { $false }
            Mock Remove-Item { }
            Mock Get-LocalUser { $null }
            Mock Invoke-WithRegistryHive { [PSCustomObject]@{ Success = $true; Result = 1; Message = $null } }
            Mock Write-OperationLog { }

            $result = Remove-UserProfileData -Context $script:liveCtx -Protected $script:protected -Confirm:$false

            $result.Removed | Should -Not -Contain 'operator'
            $result.Skipped.Name | Should -Contain 'operator'
        }

        It 'reports an incomplete wipe when a profile was skipped' {
            Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_UserProfile' } -MockWith {
                @([PSCustomObject]@{ SID = $script:protectedSid; LocalPath = 'C:\Users\operator'; Special = $false })
            }
            Mock Get-Process { @() }
            Mock Test-Path { $false }
            Mock Remove-Item { }
            Mock Get-LocalUser { $null }
            Mock Invoke-WithRegistryHive { [PSCustomObject]@{ Success = $true; Result = 0; Message = $null } }
            Mock Write-OperationLog { }

            $result = Remove-UserProfileData -Context $script:liveCtx -Protected $script:protected -Confirm:$false

            $result.Complete | Should -BeFalse -Because 'a skipped profile means the device still holds a previous user'
        }

        It 'never kills a process owned by a protected account' {
            Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_UserProfile' } -MockWith {
                @([PSCustomObject]@{ SID = $script:targetSid; LocalPath = 'C:\Users\departed'; Special = $false })
            }
            Mock Get-Process {
                @(
                    [PSCustomObject]@{ UserName = 'CONTOSO\operator'; Id = 1 }
                    [PSCustomObject]@{ UserName = 'CONTOSO\departed'; Id = 2 }
                )
            }
            Mock Stop-Process { }
            Mock Test-Path { $false }
            Mock Remove-Item { }
            Mock Get-LocalUser { $null }
            Mock Invoke-WithRegistryHive { [PSCustomObject]@{ Success = $true; Result = 1; Message = $null } }
            Mock Write-OperationLog { }

            Remove-UserProfileData -Context $script:liveCtx -Protected $script:protected -Confirm:$false | Out-Null

            # This is the exact shape of defect D1: the operator's own host being killed.
            Should -Invoke Stop-Process -Times 0 -ParameterFilter { $InputObject.UserName -eq 'CONTOSO\operator' }
        }
    }

    Context 'System and service profiles' {
        It 'never treats a non-user SID as a profile' -ForEach @(
            @{ Sid = 'S-1-5-18'; Label = 'LocalSystem' }
            @{ Sid = 'S-1-5-19'; Label = 'LocalService' }
            @{ Sid = 'S-1-5-20'; Label = 'NetworkService' }
        ) {
            $ctx = [PSCustomObject]@{
                IsOffline = $false; Valid = $true; Root = 'C:\'
                WindowsDir = 'C:\Windows'; UsersDir = 'C:\Users'; Description = 'test'
            }
            $prot = [PSCustomObject]@{ Sids = @(); Names = @(); Reasons = @{}; IsEmpty = $true }

            Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_UserProfile' } -MockWith {
                @([PSCustomObject]@{ SID = $Sid; LocalPath = 'C:\Windows\ServiceProfiles\Thing'; Special = $false })
            }
            Mock Get-Process { @() }
            Mock Write-OperationLog { }
            Mock Invoke-WithRegistryHive { [PSCustomObject]@{ Success = $true; Result = 0; Message = $null } }

            $result = Remove-UserProfileData -Context $ctx -Protected $prot -Confirm:$false
            $result.Removed.Count | Should -Be 0
        }
    }
}

# ============================================================================
# Get-ControlSetPath
# ============================================================================
Describe 'Get-ControlSetPath' {

    It 'returns CurrentControlSet for a live hive' {
        Get-ControlSetPath -HiveRoot 'HKLM:\SYSTEM' -IsOffline $false | Should -Be 'HKLM:\SYSTEM\CurrentControlSet'
    }

    It 'returns null rather than guessing when the control set cannot be determined' {
        Mock Test-Path { $false }
        Mock Get-ChildItem { @() }
        Mock Write-OperationLog { }

        Get-ControlSetPath -HiveRoot 'HKLM:\ED_SYSTEM_test' -IsOffline $true | Should -BeNullOrEmpty
    }
}

# ============================================================================
# Invoke-WithRegistryHive
# ============================================================================
Describe 'Invoke-WithRegistryHive' {

    It 'does not mount anything in live mode' {
        $ctx = [PSCustomObject]@{ IsOffline = $false; Valid = $true }
        $r = Invoke-WithRegistryHive -Context $ctx -Hive SOFTWARE -ScriptBlock { param($root) $root }

        $r.Success | Should -BeTrue
        $r.Mounted | Should -BeFalse
        $r.Result  | Should -Be 'HKLM:\SOFTWARE'
    }

    It 'hands the live path for each hive' -ForEach @(
        @{ Hive = 'SOFTWARE'; Expected = 'HKLM:\SOFTWARE' }
        @{ Hive = 'SYSTEM';   Expected = 'HKLM:\SYSTEM' }
        @{ Hive = 'SAM';      Expected = 'HKLM:\SAM' }
        @{ Hive = 'SECURITY'; Expected = 'HKLM:\SECURITY' }
    ) {
        $ctx = [PSCustomObject]@{ IsOffline = $false; Valid = $true }
        (Invoke-WithRegistryHive -Context $ctx -Hive $Hive -ScriptBlock { param($root) $root }).Result | Should -Be $Expected
    }

    It 'fails cleanly when the offline hive file is absent' {
        $ctx = [PSCustomObject]@{
            IsOffline = $true; Valid = $true
            SoftwareHive = (Join-Path $TestDrive 'no-such-hive')
        }

        $r = Invoke-WithRegistryHive -Context $ctx -Hive SOFTWARE -ScriptBlock { param($root) 'should not run' }

        $r.Success | Should -BeFalse
        $r.Mounted | Should -BeFalse
        $r.Message | Should -Match 'not found'
    }

    It 'reports failure when a scriptblock throws in live mode' {
        $ctx = [PSCustomObject]@{ IsOffline = $false; Valid = $true }
        $r = Invoke-WithRegistryHive -Context $ctx -Hive SOFTWARE -ScriptBlock { throw 'boom' }

        $r.Success | Should -BeFalse
        $r.Message | Should -Match 'boom'
    }
}

# ============================================================================
# Set-EraseDriveEvidenceRoot - defect D2
# ============================================================================
Describe 'Set-EraseDriveEvidenceRoot' {

    AfterEach {
        $Script:EraseDriveConfig.LogDirectory  = Join-Path $TestDrive 'Logs'
        $Script:EraseDriveConfig.CertDirectory = Join-Path $TestDrive 'Certs'
    }

    It 'uses an explicit path when one is given' {
        $explicit = Join-Path $TestDrive 'Evidence-Explicit'
        $r = Set-EraseDriveEvidenceRoot -Path $explicit

        $r.Success | Should -BeTrue
        $r.Source  | Should -Be 'Explicit'
        $r.Root    | Should -Be $explicit
    }

    It 'repoints the module log and certificate directories' {
        $explicit = Join-Path $TestDrive 'Evidence-Repoint'
        Set-EraseDriveEvidenceRoot -Path $explicit | Out-Null

        $Script:EraseDriveConfig.LogDirectory  | Should -Be $explicit
        $Script:EraseDriveConfig.CertDirectory | Should -Be (Join-Path $explicit 'Certificates')
    }

    It 'flags evidence that would sit on the volume being wiped' {
        # The D2 failure mode: the certificate of destruction leaving with the asset.
        $explicit = Join-Path $TestDrive 'Evidence-OnTarget'
        $ctx = [PSCustomObject]@{ Valid = $true; Root = (Split-Path -Qualifier $TestDrive) + '\' }

        (Set-EraseDriveEvidenceRoot -Path $explicit -Context $ctx).OnTargetVolume | Should -BeTrue
    }

    It 'falls through to the next candidate when a location is not writable' {
        Mock Set-Content { throw 'read-only volume' } -ParameterFilter { $LiteralPath -like '*ed_write_probe*' }
        Mock Write-OperationLog { }

        $r = Set-EraseDriveEvidenceRoot -Path (Join-Path $TestDrive 'Unwritable')
        $r.Source | Should -Not -Be 'Explicit'
    }
}

# ============================================================================
# The no-Active-Directory-write invariant
# ============================================================================
Describe 'No Active Directory writes' {

    It 'exposes no credential parameter on <Function>' -ForEach @(
        @{ Function = 'Invoke-DeviceReissueWipe' }
        @{ Function = 'Invoke-ForensicUserDataWipe' }
        @{ Function = 'Remove-DomainMembership' }
        @{ Function = 'Remove-UserProfileData' }
        @{ Function = 'Invoke-Generalize' }
    ) {
        # A domain unjoin can only touch the directory if it can authenticate, and it can
        # only authenticate with a credential. No credential in the call path means the
        # unjoin is local by construction, not by intention. This test is the enforcement.
        $cmd = Get-Command -Name $Function -CommandType Function
        $offending = @($cmd.Parameters.Values | Where-Object {
            $_.ParameterType.Name -match 'PSCredential' -or $_.Name -match 'Credential'
        })

        $offending.Count | Should -Be 0 -Because 'a credential parameter would make an AD write reachable'
    }

    It 'contains no call to an AD-modifying cmdlet anywhere in the module' {
        $forbidden = @(
            'Remove-ADComputer', 'Set-ADComputer', 'Disable-ADAccount', 'Remove-ADObject',
            'Remove-ADUser', 'Set-ADUser', 'Remove-Computer'
        )

        $hits = @()
        Get-ChildItem -Path (Join-Path (Join-Path $PSScriptRoot '..') 'EraseDrive') -Recurse -Filter '*.ps1' | ForEach-Object {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)

            $calls = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.CommandAst]
            }, $true)

            foreach ($call in $calls) {
                $name = $call.GetCommandName()
                if ($name -and $name -in $forbidden) {
                    $hits += "$($_.Name): $name"
                }
            }
        }

        $hits | Should -BeNullOrEmpty -Because 'the tool must never modify Active Directory'
    }
}

# ============================================================================
# Invoke-Generalize preflight
# ============================================================================
Describe 'Invoke-Generalize preflight' {

    It 'refuses offline targets rather than attempting sysprep' {
        $ctx = [PSCustomObject]@{ IsOffline = $true; Valid = $true; Root = 'C:\'; WindowsDir = 'C:\Windows' }
        Mock Write-OperationLog { }

        $r = Invoke-Generalize -Context $ctx -Confirm:$false

        $r.Refused | Should -BeTrue
        $r.Success | Should -BeFalse
        $r.Reason  | Should -Match 'offline|WinPE'
    }

    It 'refuses a domain-joined machine, naming the domain' {
        $ctx = [PSCustomObject]@{ IsOffline = $false; Valid = $true; Root = 'C:\'; WindowsDir = 'C:\Windows' }
        Mock Test-Path { $true }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' } -MockWith {
            [PSCustomObject]@{ PartOfDomain = $true; Domain = 'contoso.local' }
        }
        Mock Write-OperationLog { }

        $r = Invoke-Generalize -Context $ctx -Confirm:$false

        $r.Refused | Should -BeTrue
        $r.Reason  | Should -Match 'contoso.local'
    }

    It 'refuses when no rearms remain rather than consuming a failed attempt' {
        $ctx = [PSCustomObject]@{ IsOffline = $false; Valid = $true; Root = 'C:\'; WindowsDir = 'C:\Windows' }
        Mock Test-Path { $true }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' } -MockWith {
            [PSCustomObject]@{ PartOfDomain = $false; Domain = 'WORKGROUP' }
        }
        Mock Get-CimInstance -ParameterFilter { $ClassName -eq 'SoftwareLicensingService' } -MockWith {
            [PSCustomObject]@{ RemainingWindowsReArmCount = 0 }
        }
        Mock Write-OperationLog { }

        $r = Invoke-Generalize -Context $ctx -Confirm:$false

        $r.Refused | Should -BeTrue
        $r.Reason  | Should -Match 'rearm'
    }
}

# ============================================================================
# Manifest
# ============================================================================
Describe 'Manifest' {

    It 'ships <Function> as a file but does NOT export it in v3.1.0' -ForEach @(
        @{ Function = 'Invoke-DeviceReissueWipe' }
        @{ Function = 'New-EraseDriveBootMedia' }
    ) {
        # Both ship dormant. Neither has ever been executed against a real machine,
        # so neither is public API yet; they are exported in v3.2 once the VM and
        # WinPE runs pass. Asserting BOTH halves matters: the file must still ship,
        # and the manifest must not advertise it.
        $moduleDir = Join-Path (Join-Path $PSScriptRoot '..') 'EraseDrive'
        $manifest  = Import-PowerShellDataFile -Path (Join-Path $moduleDir 'EraseDrive.psd1')

        Test-Path (Join-Path (Join-Path $moduleDir 'Public') "$Function.ps1") | Should -BeTrue
        $manifest.FunctionsToExport | Should -Not -Contain $Function
    }

    It 'declares every exported function as a real file' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'EraseDrive') 'EraseDrive.psd1')
        $publicDir = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'EraseDrive') 'Public'

        foreach ($fn in $manifest.FunctionsToExport) {
            Test-Path (Join-Path $publicDir "$fn.ps1") | Should -BeTrue -Because "$fn is exported and must have a file"
        }
    }
}

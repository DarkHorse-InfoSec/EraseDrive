#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

<#
.SYNOPSIS
    Pester 5.x tests for the EraseDrive license validation layer.

.DESCRIPTION
    Exercises Test-EraseDriveLicense end-to-end with a hermetic RSA keypair generated in
    TestDrive. Tests cover: valid license, tampered payload, tampered signature, wrong
    public key, expired license, missing file, malformed JSON, unknown tier.

.NOTES
    Run with:  Invoke-Pester -Path .\Tests\License.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent

    # Dot-source the function under test so we don't import the full module
    # (the module .psm1 carries #Requires -RunAsAdministrator).
    . (Join-Path $repoRoot 'EraseDrive\Private\Test-EraseDriveLicense.ps1')

    # Generate a hermetic test keypair into TestDrive
    $script:TestKeyDir = Join-Path $TestDrive 'keys'
    New-Item -Path $script:TestKeyDir -ItemType Directory -Force | Out-Null

    $script:TestPubKeyPath = Join-Path $script:TestKeyDir 'test-public.xml'
    $script:TestPrivKeyXml = $null

    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
    try {
        $script:TestPrivKeyXml = $rsa.ToXmlString($true)
        $pubXml = $rsa.ToXmlString($false)
        [System.IO.File]::WriteAllText($script:TestPubKeyPath, $pubXml, [System.Text.Encoding]::UTF8)
    }
    finally {
        $rsa.Dispose()
    }

    # Helper: issue a license signed with the test private key
    function New-TestLicense {
        param(
            [hashtable]$Payload,
            [string]$PrivKeyXml,
            [string]$OutPath
        )
        if (-not $PrivKeyXml) { $PrivKeyXml = $script:TestPrivKeyXml }

        $payloadJson  = $Payload | ConvertTo-Json -Compress -Depth 5
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)

        $rsa2 = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        try {
            $rsa2.FromXmlString($PrivKeyXml)
            $sigBytes = $rsa2.SignData($payloadBytes, 'SHA256')
        }
        finally {
            $rsa2.Dispose()
        }

        $lic = [ordered]@{
            payload_b64   = [System.Convert]::ToBase64String($payloadBytes)
            signature_b64 = [System.Convert]::ToBase64String($sigBytes)
        }
        $licJson = $lic | ConvertTo-Json -Compress

        [System.IO.File]::WriteAllText($OutPath, $licJson, [System.Text.Encoding]::UTF8)
    }

    # Standard payload factory
    function New-StandardPayload {
        param([string]$Tier = 'Pro', [Nullable[datetime]]$ExpiresAt)
        $p = [ordered]@{
            version         = 1
            license_id      = 'EDR-TEST-00000000-00000000'
            tier            = $Tier
            issued_to       = 'Acme Test Co.'
            issued_to_email = 'test@example.com'
            purchase_id     = 'TEST-PURCHASE'
            issued_at       = [DateTime]::UtcNow.ToString('o')
            expires_at      = $(if ($ExpiresAt) { $ExpiresAt.ToUniversalTime().ToString('o') } else { $null })
        }
        return $p
    }
}

Describe 'Test-EraseDriveLicense - happy paths' {

    It 'Returns Free tier silently when no license file is present' {
        $result = Test-EraseDriveLicense -LicensePath (Join-Path $TestDrive 'does-not-exist.lic') -PublicKeyPath $script:TestPubKeyPath
        $result.Valid | Should -BeFalse
        $result.Tier  | Should -Be 'Free'
        $result.Reason | Should -Match 'No license'
    }

    It 'Validates a well-formed Pro license' {
        $licPath = Join-Path $TestDrive 'pro.lic'
        New-TestLicense -Payload (New-StandardPayload -Tier 'Pro') -OutPath $licPath

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath
        $result.Valid     | Should -BeTrue
        $result.Tier      | Should -Be 'Pro'
        $result.IssuedTo  | Should -Be 'Acme Test Co.'
        $result.LicenseId | Should -Be 'EDR-TEST-00000000-00000000'
    }

    It 'Validates a Team license with future expiry' {
        $licPath = Join-Path $TestDrive 'team.lic'
        New-TestLicense -Payload (New-StandardPayload -Tier 'Team' -ExpiresAt ([DateTime]::UtcNow.AddYears(1))) -OutPath $licPath

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath
        $result.Valid     | Should -BeTrue
        $result.Tier      | Should -Be 'Team'
        $result.ExpiresAt | Should -Not -BeNullOrEmpty
    }

    It 'Validates an MSP license' {
        $licPath = Join-Path $TestDrive 'msp.lic'
        New-TestLicense -Payload (New-StandardPayload -Tier 'MSP') -OutPath $licPath

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath
        $result.Valid | Should -BeTrue
        $result.Tier  | Should -Be 'MSP'
    }
}

Describe 'Test-EraseDriveLicense - rejection paths' {

    It 'Rejects a license with a tampered payload (verification fails)' {
        $licPath = Join-Path $TestDrive 'tampered-payload.lic'
        New-TestLicense -Payload (New-StandardPayload -Tier 'Pro') -OutPath $licPath

        # Tamper: read the JSON, replace the payload base64 with a different valid base64 string
        $licJson = [System.IO.File]::ReadAllText($licPath, [System.Text.Encoding]::UTF8)
        $lic = $licJson | ConvertFrom-Json
        $tampered = New-StandardPayload -Tier 'MSP'
        $tampered.license_id = 'EDR-MSP-FRAUDULENT'
        $tamperedJson = $tampered | ConvertTo-Json -Compress -Depth 5
        $lic.payload_b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($tamperedJson))
        $licOut = $lic | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText($licPath, $licOut, [System.Text.Encoding]::UTF8)

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath -Silent
        $result.Valid  | Should -BeFalse
        $result.Tier   | Should -Be 'Free'
        $result.Reason | Should -Match 'Signature verification failed'
    }

    It 'Rejects a license with a tampered signature' {
        $licPath = Join-Path $TestDrive 'tampered-sig.lic'
        New-TestLicense -Payload (New-StandardPayload -Tier 'Pro') -OutPath $licPath

        $licJson = [System.IO.File]::ReadAllText($licPath, [System.Text.Encoding]::UTF8)
        $lic = $licJson | ConvertFrom-Json
        # Flip a byte in the signature
        $sigBytes = [System.Convert]::FromBase64String($lic.signature_b64)
        $sigBytes[0] = $sigBytes[0] -bxor 0xFF
        $lic.signature_b64 = [System.Convert]::ToBase64String($sigBytes)
        $licOut = $lic | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText($licPath, $licOut, [System.Text.Encoding]::UTF8)

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath -Silent
        $result.Valid  | Should -BeFalse
        $result.Tier   | Should -Be 'Free'
        $result.Reason | Should -Match 'Signature verification failed'
    }

    It 'Rejects a license signed by a different (wrong) key' {
        # Issue with a DIFFERENT private key
        $wrongRsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
        try {
            $wrongPrivXml = $wrongRsa.ToXmlString($true)
        }
        finally {
            $wrongRsa.Dispose()
        }

        $licPath = Join-Path $TestDrive 'wrong-key.lic'
        New-TestLicense -Payload (New-StandardPayload -Tier 'Pro') -PrivKeyXml $wrongPrivXml -OutPath $licPath

        # Verify with the REAL test public key (different from $wrongPrivXml's public)
        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath -Silent
        $result.Valid | Should -BeFalse
        $result.Tier  | Should -Be 'Free'
        $result.Reason | Should -Match 'Signature verification failed'
    }

    It 'Rejects an expired license' {
        $licPath = Join-Path $TestDrive 'expired.lic'
        # Expired one day ago
        New-TestLicense -Payload (New-StandardPayload -Tier 'Team' -ExpiresAt ([DateTime]::UtcNow.AddDays(-1))) -OutPath $licPath

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath -Silent
        $result.Valid  | Should -BeFalse
        $result.Tier   | Should -Be 'Free'
        $result.Reason | Should -Match 'expired'
        # Identification fields should still surface from the (otherwise-valid) signature
        $result.LicenseId | Should -Be 'EDR-TEST-00000000-00000000'
    }

    It 'Rejects a license with an unknown tier' {
        $licPath = Join-Path $TestDrive 'bad-tier.lic'
        $bad = New-StandardPayload -Tier 'Pro'
        $bad.tier = 'Enterprise'  # not in allowed set
        New-TestLicense -Payload $bad -OutPath $licPath

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath -Silent
        $result.Valid  | Should -BeFalse
        $result.Tier   | Should -Be 'Free'
        $result.Reason | Should -Match "Unknown tier"
    }

    It 'Rejects a malformed license file (not JSON)' {
        $licPath = Join-Path $TestDrive 'malformed.lic'
        [System.IO.File]::WriteAllText($licPath, 'this is not valid JSON', [System.Text.Encoding]::UTF8)

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath -Silent
        $result.Valid | Should -BeFalse
        $result.Tier  | Should -Be 'Free'
    }

    It 'Rejects a license missing required fields' {
        $licPath = Join-Path $TestDrive 'missing-fields.lic'
        $licJson = (@{ foo = 'bar' } | ConvertTo-Json -Compress)
        [System.IO.File]::WriteAllText($licPath, $licJson, [System.Text.Encoding]::UTF8)

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath -Silent
        $result.Valid  | Should -BeFalse
        $result.Tier   | Should -Be 'Free'
        $result.Reason | Should -Match 'payload_b64|signature_b64'
    }

    It 'Returns Free with a warning when the public key file is missing' {
        $licPath = Join-Path $TestDrive 'valid.lic'
        New-TestLicense -Payload (New-StandardPayload -Tier 'Pro') -OutPath $licPath

        $missingPubKey = Join-Path $TestDrive 'no-such-key.xml'

        $result = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $missingPubKey -Silent
        $result.Valid  | Should -BeFalse
        $result.Tier   | Should -Be 'Free'
        $result.Reason | Should -Match 'Public key not found'
    }
}

Describe 'Test-EraseDriveLicense - silent mode' {

    It 'Suppresses warnings when -Silent is passed even on rejection' {
        $licPath = Join-Path $TestDrive 'silent-test.lic'
        New-TestLicense -Payload (New-StandardPayload -Tier 'Pro') -OutPath $licPath

        $licJson = [System.IO.File]::ReadAllText($licPath, [System.Text.Encoding]::UTF8)
        $lic = $licJson | ConvertFrom-Json
        $sigBytes = [System.Convert]::FromBase64String($lic.signature_b64)
        $sigBytes[0] = $sigBytes[0] -bxor 0xFF
        $lic.signature_b64 = [System.Convert]::ToBase64String($sigBytes)
        [System.IO.File]::WriteAllText($licPath, ($lic | ConvertTo-Json -Compress), [System.Text.Encoding]::UTF8)

        # The warning stream should be empty when -Silent is used
        $warnings = $null
        $null = Test-EraseDriveLicense -LicensePath $licPath -PublicKeyPath $script:TestPubKeyPath -Silent -WarningVariable warnings -WarningAction SilentlyContinue
        $warnings | Should -BeNullOrEmpty
    }
}

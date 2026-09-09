#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

<#
.SYNOPSIS
    Pester tests for the hand-crafted PDF Certificate of Destruction generator and the
    license-gated cert-output behavior in New-ErasureCertificate.

.NOTES
    Run with:  Invoke-Pester -Path .\Tests\PdfCertificate.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $repoRoot = Split-Path $PSScriptRoot -Parent

    # Hermetic per-test config for the module-scope variable
    $Script:EraseDriveConfig = @{
        LogDirectory   = Join-Path $TestDrive 'Logs'
        LogFile        = Join-Path (Join-Path $TestDrive 'Logs') 'EraseDrive.log'
        CertDirectory  = Join-Path $TestDrive 'Certs'
        LicensePath    = Join-Path $TestDrive 'license.lic'
        PublicKeyPath  = Join-Path $TestDrive 'public.xml'
        MaxLogSizeMB   = 1
        MaxLogFiles    = 3
        Version        = '3.1.0'
    }
    New-Item -Path $Script:EraseDriveConfig.LogDirectory -ItemType Directory -Force | Out-Null
    New-Item -Path $Script:EraseDriveConfig.CertDirectory -ItemType Directory -Force | Out-Null

    # Generate a hermetic keypair for license signing
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
    try {
        $script:TestPrivKeyXml = $rsa.ToXmlString($true)
        $pubXml = $rsa.ToXmlString($false)
        [System.IO.File]::WriteAllText($Script:EraseDriveConfig.PublicKeyPath, $pubXml, [System.Text.Encoding]::UTF8)
    }
    finally {
        $rsa.Dispose()
    }

    # Dot-source all module functions (avoid the .psm1 -RunAsAdministrator gate)
    Get-ChildItem (Join-Path $repoRoot 'EraseDrive\Private') -Filter '*.ps1' | ForEach-Object { . $_.FullName }
    Get-ChildItem (Join-Path $repoRoot 'EraseDrive\Public') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

    # Helper: write a license file with our test private key
    function Set-TestLicense {
        param(
            [string]$Tier = 'Pro',
            [string]$IssuedTo = 'Test Customer'
        )
        $payload = [ordered]@{
            version         = 1
            license_id      = 'EDR-TEST-PDF-01'
            tier            = $Tier
            issued_to       = $IssuedTo
            issued_to_email = 'test@example.com'
            purchase_id     = 'TEST-PDF'
            issued_at       = [DateTime]::UtcNow.ToString('o')
            expires_at      = $null
        }
        $payloadJson  = $payload | ConvertTo-Json -Compress -Depth 5
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)

        $rsa2 = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        try {
            $rsa2.FromXmlString($script:TestPrivKeyXml)
            $sigBytes = $rsa2.SignData($payloadBytes, 'SHA256')
        }
        finally {
            $rsa2.Dispose()
        }

        $lic = [ordered]@{
            payload_b64   = [System.Convert]::ToBase64String($payloadBytes)
            signature_b64 = [System.Convert]::ToBase64String($sigBytes)
        }
        [System.IO.File]::WriteAllText(
            $Script:EraseDriveConfig.LicensePath,
            ($lic | ConvertTo-Json -Compress),
            [System.Text.Encoding]::UTF8
        )
    }

    function Remove-TestLicense {
        if (Test-Path -LiteralPath $Script:EraseDriveConfig.LicensePath) {
            Remove-Item -LiteralPath $Script:EraseDriveConfig.LicensePath -Force
        }
    }
}

# Each test starts with no license; opt in via Set-TestLicense.
BeforeEach {
    Remove-TestLicense
}

Describe 'New-PdfCertificate - PDF structure' {

    It 'Writes a file that starts with %PDF-1.4 and ends with %%EOF' {
        $pdfPath = Join-Path $TestDrive 'structure.pdf'
        $result = New-PdfCertificate `
            -OutPath          $pdfPath `
            -CertificateId    ([guid]::NewGuid()) `
            -Timestamp        ([DateTime]::UtcNow) `
            -OperationType    'DiskErase' `
            -TargetDescription 'Test target' `
            -Method           'Secure' `
            -MethodDescription 'Test method' `
            -DiskSerial       'SN-001' `
            -DiskModel        'Test Model' `
            -DiskSizeGB       500.0 `
            -VerificationResult ([PSCustomObject]@{ Verified = $true; SamplesChecked = 100; SamplesPassed = 100; SamplesFailed = 0 }) `
            -OperatorName     'TEST\operator' `
            -MachineName      'TEST-MACHINE' `
            -ToolVersion      '3.1.0' `
            -HmacHex          ('a' * 64) `
            -LicenseTier      'Pro' `
            -LicenseId        'EDR-TEST-PDF-01' `
            -LicenseIssuedTo  'Test Customer'

        $result.Success | Should -BeTrue
        Test-Path -LiteralPath $pdfPath | Should -BeTrue

        $bytes = [System.IO.File]::ReadAllBytes($pdfPath)
        $head = [System.Text.Encoding]::ASCII.GetString($bytes, 0, [Math]::Min($bytes.Length, 8))
        $head | Should -Match '^%PDF-1\.'

        $tail = [System.Text.Encoding]::ASCII.GetString($bytes, [Math]::Max(0, $bytes.Length - 32), [Math]::Min($bytes.Length, 32))
        $tail | Should -Match '%%EOF\s*$'
    }

    It 'Contains the certificate ID and HMAC hex in metadata-bearing form' {
        $certId = [guid]::NewGuid()
        $hmacHex = 'b' * 64
        $pdfPath = Join-Path $TestDrive 'metadata.pdf'

        $null = New-PdfCertificate `
            -OutPath $pdfPath `
            -CertificateId $certId `
            -Timestamp ([DateTime]::UtcNow) `
            -OperationType 'DiskErase' `
            -TargetDescription 'X' `
            -Method 'Secure' `
            -MethodDescription 'X' `
            -OperatorName 'X' `
            -MachineName 'X' `
            -ToolVersion '3.1.0' `
            -HmacHex $hmacHex `
            -LicenseTier 'Pro' `
            -LicenseId 'X' `
            -LicenseIssuedTo 'X'

        $content = [System.IO.File]::ReadAllText($pdfPath, [System.Text.Encoding]::ASCII)
        $content | Should -Match ([regex]::Escape($certId.ToString()))
        $content | Should -Match ([regex]::Escape($hmacHex))
    }

    It 'Embeds the expected base-14 fonts (Helvetica, Helvetica-Bold, Courier)' {
        $pdfPath = Join-Path $TestDrive 'fonts.pdf'
        $null = New-PdfCertificate `
            -OutPath $pdfPath `
            -CertificateId ([guid]::NewGuid()) `
            -Timestamp ([DateTime]::UtcNow) `
            -OperationType 'DiskErase' `
            -TargetDescription 'X' `
            -Method 'Secure' `
            -MethodDescription 'X' `
            -OperatorName 'X' `
            -MachineName 'X' `
            -ToolVersion '3.1.0' `
            -HmacHex ('c' * 64) `
            -LicenseTier 'Pro' `
            -LicenseId 'X' `
            -LicenseIssuedTo 'X'

        $content = [System.IO.File]::ReadAllText($pdfPath, [System.Text.Encoding]::ASCII)
        $content | Should -Match '/BaseFont /Helvetica\b'
        $content | Should -Match '/BaseFont /Helvetica-Bold\b'
        $content | Should -Match '/BaseFont /Courier\b'
    }

    It 'Escapes parentheses and backslashes in user-supplied strings' {
        $pdfPath = Join-Path $TestDrive 'escape.pdf'
        $null = New-PdfCertificate `
            -OutPath $pdfPath `
            -CertificateId ([guid]::NewGuid()) `
            -Timestamp ([DateTime]::UtcNow) `
            -OperationType 'DiskErase' `
            -TargetDescription 'Disk 1 (Samsung SSD) \\.\PhysicalDrive1' `
            -Method 'Secure' `
            -MethodDescription 'X' `
            -OperatorName 'X' `
            -MachineName 'X' `
            -ToolVersion '3.1.0' `
            -HmacHex ('d' * 64) `
            -LicenseTier 'Pro' `
            -LicenseId 'X' `
            -LicenseIssuedTo 'X'

        $content = [System.IO.File]::ReadAllText($pdfPath, [System.Text.Encoding]::ASCII)
        # PDF strings must escape '(' as '\(' and ')' as '\)'
        $content | Should -Match '\\\(Samsung SSD\\\)'
    }
}

Describe 'New-ErasureCertificate - license gating' {

    It 'Free tier: writes .txt only, no .pdf' {
        # Ensure no license file exists
        $result = New-ErasureCertificate `
            -OperationType 'DiskErase' `
            -TargetDescription 'Test target' `
            -Method 'Standard' `
            -OperatorName 'TEST\op'

        $result.Success     | Should -BeTrue
        $result.LicenseTier | Should -Be 'Free'
        $result.FilePath    | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $result.FilePath | Should -BeTrue
        $result.PdfFilePath | Should -BeNullOrEmpty

        # .txt body should mention the Free tier
        $body = [System.IO.File]::ReadAllText($result.FilePath, [System.Text.Encoding]::UTF8)
        $body | Should -Match 'Free \(no license\)'
    }

    It 'Pro tier: writes both .txt and .pdf' {
        Set-TestLicense -Tier 'Pro' -IssuedTo 'Acme Refurb, Inc.'

        $result = New-ErasureCertificate `
            -OperationType 'DiskErase' `
            -TargetDescription 'Pro tier test' `
            -Method 'Secure' `
            -OperatorName 'TEST\op'

        $result.Success     | Should -BeTrue
        $result.LicenseTier | Should -Be 'Pro'
        $result.FilePath    | Should -Not -BeNullOrEmpty
        $result.PdfFilePath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $result.FilePath | Should -BeTrue
        Test-Path -LiteralPath $result.PdfFilePath | Should -BeTrue

        # .pdf should be a real PDF (starts with %PDF-)
        $pdfHead = [System.Text.Encoding]::ASCII.GetString(
            [System.IO.File]::ReadAllBytes($result.PdfFilePath)[0..7]
        )
        $pdfHead | Should -Match '^%PDF-'

        # .txt body should include the license block
        $body = [System.IO.File]::ReadAllText($result.FilePath, [System.Text.Encoding]::UTF8)
        $body | Should -Match 'License ID:.*EDR-TEST-PDF-01'
        $body | Should -Match 'Issued To:.*Acme Refurb, Inc\.'
    }

    It 'Team tier: writes both .txt and .pdf with Team tier label' {
        Set-TestLicense -Tier 'Team' -IssuedTo 'Vermont MSP, LLC'

        $result = New-ErasureCertificate `
            -OperationType 'UserWipe' `
            -TargetDescription 'Team tier test' `
            -Method 'Standard' `
            -OperatorName 'TEST\op'

        $result.LicenseTier | Should -Be 'Team'
        $result.PdfFilePath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $result.PdfFilePath | Should -BeTrue
    }

    It 'Integrity signature on .txt remains valid after the LICENSE block is included' {
        Set-TestLicense -Tier 'Pro' -IssuedTo 'Integrity Test'

        $result = New-ErasureCertificate `
            -OperationType 'DiskErase' `
            -TargetDescription 'Integrity test target' `
            -Method 'Secure' `
            -OperatorName 'TEST\op'

        $check = Test-CertificateIntegrity -CertificatePath $result.FilePath
        $check.Valid | Should -BeTrue -Because 'HMAC must verify over the .txt payload, including the new LICENSE block'
    }
}

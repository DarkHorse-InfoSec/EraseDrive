#Requires -Version 5.1

<#
.SYNOPSIS
    Issues a signed EraseDrive license file for a single customer.

.DESCRIPTION
    Builds a JSON payload (customer name, email, tier, purchase ID, timestamps), signs it
    with the issuer's RSA private key using RSA-SHA256 (PKCS#1 v1.5), and writes a single
    .lic file containing the base64-encoded payload and signature. Attach the .lic file
    to the customer's purchase-confirmation email.

.PARAMETER CustomerName
    Customer or company name printed on certificates (e.g., "Acme MSP, Inc.").

.PARAMETER CustomerEmail
    Customer contact email. Stored in the license for audit/recovery.

.PARAMETER Tier
    One of: Pro, Team, MSP.

.PARAMETER PurchaseId
    Gumroad or Lemon Squeezy order ID. Stored for audit / refund correlation.

.PARAMETER LicenseId
    Optional. Auto-generated as EDR-<Tier>-<UTCTimestamp>-<Random8> if omitted.

.PARAMETER ExpiresAt
    Optional. UTC expiry date. Omit for perpetual licenses (Pro lifetime).
    Recommended for Team/MSP annual subscriptions.

.PARAMETER PrivateKeyPath
    REQUIRED. Path to the RSA private-key XML produced by New-EraseDriveLicenseKeyPair.ps1.

.PARAMETER OutPath
    Optional. Path for the output .lic file. Defaults to
    .\EraseDrive-License-<Customer>-<LicenseId>.lic in the current directory.

.EXAMPLE
    .\New-EraseDriveLicense.ps1 `
        -CustomerName 'Acme Refurb' `
        -CustomerEmail 'ops@acmerefurb.com' `
        -Tier Pro `
        -PurchaseId 'GUMROAD-ABC123' `
        -PrivateKeyPath 'C:\Users\me\Secrets\EraseDrive\license-private.xml'

.EXAMPLE
    .\New-EraseDriveLicense.ps1 `
        -CustomerName 'Vermont MSP, LLC' `
        -CustomerEmail 'admin@vmsp.example' `
        -Tier Team `
        -PurchaseId 'GUMROAD-XYZ789' `
        -ExpiresAt (Get-Date).AddYears(1) `
        -PrivateKeyPath 'C:\Users\me\Secrets\EraseDrive\license-private.xml'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CustomerName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CustomerEmail,

    [Parameter(Mandatory)]
    [ValidateSet('Pro', 'Team', 'MSP')]
    [string]$Tier,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PurchaseId,

    [string]$LicenseId,

    [Nullable[datetime]]$ExpiresAt,

    [Parameter(Mandatory)]
    [string]$PrivateKeyPath,

    [string]$OutPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)) {
    throw "Private key not found at '$PrivateKeyPath'."
}

if (-not $LicenseId) {
    $ts = [DateTime]::UtcNow.ToString('yyyyMMddHHmmss')
    $rand = ([guid]::NewGuid().ToString('N')).Substring(0, 8).ToUpperInvariant()
    $LicenseId = "EDR-$Tier-$ts-$rand"
}

$payload = [ordered]@{
    version         = 1
    license_id      = $LicenseId
    tier            = $Tier
    issued_to       = $CustomerName
    issued_to_email = $CustomerEmail
    purchase_id     = $PurchaseId
    issued_at       = [DateTime]::UtcNow.ToString('o')
    expires_at      = $null
}

if ($PSBoundParameters.ContainsKey('ExpiresAt') -and $null -ne $ExpiresAt) {
    $payload.expires_at = $ExpiresAt.ToUniversalTime().ToString('o')
}

# Serialize payload as compact JSON (single line, UTF-8). The exact byte stream is what
# we sign and what the verifier will recompute over. We never re-parse-and-re-emit before
# signing - we sign the bytes we will store.
$payloadJson  = $payload | ConvertTo-Json -Compress -Depth 5
$payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)

$privXml = [System.IO.File]::ReadAllText($PrivateKeyPath, [System.Text.Encoding]::UTF8)
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
try {
    $rsa.FromXmlString($privXml)
    $sigBytes = $rsa.SignData($payloadBytes, 'SHA256')
}
finally {
    $rsa.Dispose()
}

$lic = [ordered]@{
    payload_b64   = [System.Convert]::ToBase64String($payloadBytes)
    signature_b64 = [System.Convert]::ToBase64String($sigBytes)
}
$licJson = $lic | ConvertTo-Json -Compress

if (-not $OutPath) {
    $safeName = ($CustomerName -replace '[^\w\-]', '_')
    $OutPath = Join-Path (Get-Location).Path "EraseDrive-License-$safeName-$LicenseId.lic"
}

[System.IO.File]::WriteAllText($OutPath, $licJson, [System.Text.Encoding]::UTF8)

Write-Host "License issued:" -ForegroundColor Green
Write-Host "  License ID:   $LicenseId" -ForegroundColor Cyan
Write-Host "  Tier:         $Tier" -ForegroundColor Cyan
Write-Host "  Issued To:    $CustomerName <$CustomerEmail>" -ForegroundColor Cyan
Write-Host "  Purchase ID:  $PurchaseId" -ForegroundColor Cyan
$expiryDisplay = if ($payload.expires_at) {
    ([DateTime]::Parse($payload.expires_at, [System.Globalization.CultureInfo]::InvariantCulture)).ToString('yyyy-MM-dd')
} else {
    'Never (perpetual)'
}
Write-Host "  Expires:      $expiryDisplay" -ForegroundColor Cyan
Write-Host "  File:         $OutPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Attach this .lic file to the customer's purchase-confirmation email." -ForegroundColor Yellow
Write-Host "Instructions to include:" -ForegroundColor Yellow
Write-Host "  Save license.lic to %ProgramData%\DarkHorse\EraseDrive\ then launch EraseDrive." -ForegroundColor Yellow
Write-Host "  Or use the 'Load License...' button in the GUI." -ForegroundColor Yellow

#Requires -Version 5.1

<#
.SYNOPSIS
    Verifies a freshly-issued .lic file before sending it to a customer.

.DESCRIPTION
    Convenience dev-side wrapper that loads the public key from the repo, runs the same
    Test-EraseDriveLicense function the shipped module uses, and prints the result. Use
    this as a sanity check after New-EraseDriveLicense to confirm the file you are about
    to email is well-formed and verifies under the production public key.

.PARAMETER LicensePath
    Path to the .lic file to verify.

.PARAMETER PublicKeyPath
    Optional. Defaults to <repo-root>/EraseDrive/EraseDriveLicense.pub.

.EXAMPLE
    .\Test-IssuedLicense.ps1 -LicensePath .\EraseDrive-License-Acme-EDR-Pro-...lic
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$LicensePath,

    [string]$PublicKeyPath
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent

if (-not $PublicKeyPath) {
    $PublicKeyPath = Join-Path $repoRoot 'EraseDrive\EraseDriveLicense.pub'
}

$testFn = Join-Path $repoRoot 'EraseDrive\Private\Test-EraseDriveLicense.ps1'
if (-not (Test-Path -LiteralPath $testFn -PathType Leaf)) {
    throw "Cannot find Test-EraseDriveLicense.ps1 at '$testFn'."
}

. $testFn

$result = Test-EraseDriveLicense -LicensePath $LicensePath -PublicKeyPath $PublicKeyPath

if ($result.Valid) {
    Write-Host "License is VALID." -ForegroundColor Green
}
else {
    Write-Host "License is NOT VALID." -ForegroundColor Red
    Write-Host "  Reason: $($result.Reason)" -ForegroundColor Red
}

$result | Format-List

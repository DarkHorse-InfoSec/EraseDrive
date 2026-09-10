#Requires -Version 5.1

<#
.SYNOPSIS
    One-time generator for the EraseDrive license-signing RSA keypair.

.DESCRIPTION
    Generates an RSA-2048 keypair used to sign and verify EraseDrive Pro / Team / MSP
    licenses. The PUBLIC key is written into the repo at EraseDrive/EraseDriveLicense.pub
    so it ships embedded in the module. The PRIVATE key is written ONLY to the path you
    pass via -PrivateKeyOutPath, which MUST be outside the repo (this script refuses to
    write the private key anywhere inside the repository).

    Run this exactly once per release line. If you regenerate the keypair you invalidate
    every previously-issued customer license.

.PARAMETER PrivateKeyOutPath
    REQUIRED. Absolute path where the private key XML will be written. Must NOT be inside
    the repository. Recommendation: a folder backed up to your password manager (e.g.,
    C:\Users\<you>\Secrets\EraseDrive\license-private.xml).

.PARAMETER PublicKeyOutPath
    Optional. Path where the public key XML will be written. Defaults to
    <repo-root>/EraseDrive/EraseDriveLicense.pub.

.PARAMETER Force
    Required to overwrite existing key files. Use only when intentionally rotating keys.

.EXAMPLE
    .\New-EraseDriveLicenseKeyPair.ps1 -PrivateKeyOutPath 'C:\Users\me\Secrets\EraseDrive\license-private.xml'

.NOTES
    Output format is .NET's native RSA XML so the verifier (Test-EraseDriveLicense) can
    load it via RSACryptoServiceProvider.FromXmlString without any third-party PEM parser.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PrivateKeyOutPath,

    [string]$PublicKeyOutPath,

    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent

if (-not $PublicKeyOutPath) {
    $PublicKeyOutPath = Join-Path $repoRoot 'EraseDrive\EraseDriveLicense.pub'
}

# Safety: refuse to write the private key anywhere inside the repo.
$privAbs = [System.IO.Path]::GetFullPath($PrivateKeyOutPath)
$repoAbs = [System.IO.Path]::GetFullPath($repoRoot)
if ($privAbs.StartsWith($repoAbs, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "REFUSED: Private key path '$privAbs' is inside the repo at '$repoAbs'. Choose a path outside the repo (e.g., a folder backed up to your password manager)."
}

if ((Test-Path -LiteralPath $privAbs) -and -not $Force) {
    throw "Private key already exists at '$privAbs'. Pass -Force to overwrite. NOTE: overwriting invalidates every previously-issued customer license."
}

if ((Test-Path -LiteralPath $PublicKeyOutPath) -and -not $Force) {
    throw "Public key already exists at '$PublicKeyOutPath'. Pass -Force to overwrite. NOTE: overwriting invalidates every previously-issued customer license."
}

Write-Host "Generating RSA-2048 keypair for EraseDrive license signing..." -ForegroundColor Cyan

$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
try {
    $privXml = $rsa.ToXmlString($true)
    $pubXml  = $rsa.ToXmlString($false)
}
finally {
    $rsa.Dispose()
}

$pubDir = Split-Path $PublicKeyOutPath -Parent
if ($pubDir -and -not (Test-Path -LiteralPath $pubDir)) {
    New-Item -Path $pubDir -ItemType Directory -Force | Out-Null
}
[System.IO.File]::WriteAllText($PublicKeyOutPath, $pubXml, [System.Text.Encoding]::UTF8)
Write-Host "Public key written to: $PublicKeyOutPath" -ForegroundColor Green

$privDir = Split-Path $privAbs -Parent
if ($privDir -and -not (Test-Path -LiteralPath $privDir)) {
    New-Item -Path $privDir -ItemType Directory -Force | Out-Null
}
[System.IO.File]::WriteAllText($privAbs, $privXml, [System.Text.Encoding]::UTF8)

# Best-effort: restrict ACL on the private key to the current user.
try {
    $acl = Get-Acl -LiteralPath $privAbs
    $acl.SetAccessRuleProtection($true, $false)
    $identity = if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) {
        "$env:USERDOMAIN\$env:USERNAME"
    } else {
        "$env:COMPUTERNAME\$env:USERNAME"
    }
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $privAbs -AclObject $acl
}
catch {
    Write-Warning "Could not set restrictive ACL on the private key. Verify file permissions manually: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Private key written to: $privAbs" -ForegroundColor Yellow
Write-Host ""
Write-Host "CRITICAL NEXT STEPS:" -ForegroundColor Red
Write-Host "  1. Back up '$privAbs' to your password manager NOW." -ForegroundColor Red
Write-Host "  2. Anyone with this file can issue valid EraseDrive licenses." -ForegroundColor Red
Write-Host "  3. If lost: you cannot revoke existing licenses; you must rotate keys (and re-issue every customer license)." -ForegroundColor Red
Write-Host "  4. If leaked: rotate immediately." -ForegroundColor Red
Write-Host ""
Write-Host "Commit the public key:" -ForegroundColor Cyan
Write-Host "  git add EraseDrive/EraseDriveLicense.pub" -ForegroundColor Cyan
Write-Host "  git commit -m 'add: EraseDrive license public key'" -ForegroundColor Cyan

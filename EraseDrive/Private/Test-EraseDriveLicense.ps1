function Test-EraseDriveLicense {
    <#
    .SYNOPSIS
        Validates an EraseDrive license file and returns the active license tier.

    .DESCRIPTION
        Reads a single-file .lic license (JSON with base64-encoded payload + signature),
        verifies the RSA-SHA256 (PKCS#1 v1.5) signature against the embedded public key,
        and returns the license tier and metadata.

        When no license file is present, returns a Free-tier result silently. When a
        license file is present but invalid (tampered, expired, signed by an unknown key,
        or malformed), returns a Free-tier result and emits a warning.

        Default license search order:
          1. %ProgramData%\DarkHorse\EraseDrive\license.lic
          2. <RepoRoot>\license.lic (when running directly from source)

        Default public-key path:
          $Script:EraseDriveConfig.PublicKeyPath, or
          <ModuleRoot>\EraseDriveLicense.pub

    .PARAMETER LicensePath
        Optional explicit path to a .lic file. When omitted, the default search order is used.

    .PARAMETER PublicKeyPath
        Optional explicit path to the RSA public-key XML file. When omitted, the module
        config or convention is used.

    .PARAMETER Silent
        Suppress the Write-Warning emitted for invalid-but-present license files.

    .OUTPUTS
        PSCustomObject with these properties:
            Valid          [bool]
            Tier           [string]  one of Free, Pro, Team, MSP
            LicenseId      [string]
            IssuedTo       [string]
            IssuedToEmail  [string]
            PurchaseId     [string]
            IssuedAt       [string]  ISO-8601 UTC
            ExpiresAt      [datetime] or $null
            Reason         [string]
            LicensePath    [string]

    .EXAMPLE
        Test-EraseDriveLicense

        Validates the license at the default location and returns the active tier.

    .EXAMPLE
        Test-EraseDriveLicense -LicensePath C:\Path\To\license.lic

        Validates a specific license file.
    #>
    [CmdletBinding()]
    param(
        [string]$LicensePath,
        [string]$PublicKeyPath,
        [switch]$Silent
    )

    $freeResult = [PSCustomObject]@{
        Valid         = $false
        Tier          = 'Free'
        LicenseId     = $null
        IssuedTo      = $null
        IssuedToEmail = $null
        PurchaseId    = $null
        IssuedAt      = $null
        ExpiresAt     = $null
        Reason        = 'No license file present'
        LicensePath   = $null
    }

    # ── Resolve license path ─────────────────────────────────────────────
    if (-not $LicensePath) {
        $candidates = @()

        # The loaded module configuration is authoritative. The public key
        # resolution below already prefers it; leaving it out here gave one
        # value two sources of truth, so a redirected LicensePath was silently
        # ignored and every license read as Free.
        if ($Script:EraseDriveConfig -and $Script:EraseDriveConfig.LicensePath) {
            $candidates += $Script:EraseDriveConfig.LicensePath
        }

        $candidates += (Join-Path $env:ProgramData 'DarkHorse\EraseDrive\license.lic')

        # Add repo-root fallback when running from a checked-out source tree
        try {
            $moduleRoot = Split-Path $PSScriptRoot -Parent
            $repoRoot = Split-Path $moduleRoot -Parent
            if ($repoRoot) {
                $candidates += (Join-Path $repoRoot 'license.lic')
            }
        }
        catch { }

        foreach ($c in $candidates) {
            if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) {
                $LicensePath = $c
                break
            }
        }
    }

    if (-not $LicensePath -or -not (Test-Path -LiteralPath $LicensePath -PathType Leaf)) {
        # Normal case: no license -> Free tier, silent
        return $freeResult
    }

    # ── Resolve public-key path ──────────────────────────────────────────
    if (-not $PublicKeyPath) {
        if ($Script:EraseDriveConfig -and $Script:EraseDriveConfig.PublicKeyPath) {
            $PublicKeyPath = $Script:EraseDriveConfig.PublicKeyPath
        }
        else {
            $PublicKeyPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'EraseDriveLicense.pub'
        }
    }

    if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
        if (-not $Silent) {
            Write-Warning "EraseDrive public key not found at '$PublicKeyPath'. Treating as Free tier."
        }
        $result = $freeResult.PSObject.Copy()
        $result.Reason = "Public key not found at '$PublicKeyPath'"
        $result.LicensePath = $LicensePath
        return $result
    }

    try {
        # ── Read license file ────────────────────────────────────────────
        $licJson = [System.IO.File]::ReadAllText($LicensePath, [System.Text.Encoding]::UTF8)
        $lic = $licJson | ConvertFrom-Json

        if (-not $lic.payload_b64 -or -not $lic.signature_b64) {
            throw 'License file is missing payload_b64 or signature_b64'
        }

        $payloadBytes = [System.Convert]::FromBase64String($lic.payload_b64)
        $sigBytes = [System.Convert]::FromBase64String($lic.signature_b64)

        # ── Load public key and verify ───────────────────────────────────
        $pubKeyXml = [System.IO.File]::ReadAllText($PublicKeyPath, [System.Text.Encoding]::UTF8)
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        try {
            $rsa.FromXmlString($pubKeyXml)
            $verified = $rsa.VerifyData($payloadBytes, 'SHA256', $sigBytes)
        }
        finally {
            $rsa.Dispose()
        }

        if (-not $verified) {
            throw 'Signature verification failed (payload may have been tampered with, or license was signed by a different key)'
        }

        # ── Parse payload ────────────────────────────────────────────────
        $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
        $payload = $payloadJson | ConvertFrom-Json

        $tier = [string]$payload.tier
        if ($tier -notin @('Pro', 'Team', 'MSP')) {
            throw "Unknown tier '$tier' in license payload"
        }

        # ── Expiry check ─────────────────────────────────────────────────
        $expiresAt = $null
        if ($payload.expires_at) {
            $expiresAt = [DateTime]::Parse(
                $payload.expires_at,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind
            )

            if ($expiresAt.ToUniversalTime() -lt [DateTime]::UtcNow) {
                if (-not $Silent) {
                    Write-Warning "EraseDrive license expired on $($expiresAt.ToString('yyyy-MM-dd')). Treating as Free tier."
                }
                return [PSCustomObject]@{
                    Valid         = $false
                    Tier          = 'Free'
                    LicenseId     = $payload.license_id
                    IssuedTo      = $payload.issued_to
                    IssuedToEmail = $payload.issued_to_email
                    PurchaseId    = $payload.purchase_id
                    IssuedAt      = $payload.issued_at
                    ExpiresAt     = $expiresAt
                    Reason        = "License expired on $($expiresAt.ToString('yyyy-MM-dd'))"
                    LicensePath   = $LicensePath
                }
            }
        }

        return [PSCustomObject]@{
            Valid         = $true
            Tier          = $tier
            LicenseId     = [string]$payload.license_id
            IssuedTo      = [string]$payload.issued_to
            IssuedToEmail = [string]$payload.issued_to_email
            PurchaseId    = [string]$payload.purchase_id
            IssuedAt      = [string]$payload.issued_at
            ExpiresAt     = $expiresAt
            Reason        = 'License valid'
            LicensePath   = $LicensePath
        }
    }
    catch {
        if (-not $Silent) {
            Write-Warning "EraseDrive license validation failed: $($_.Exception.Message). Treating as Free tier."
        }
        $result = $freeResult.PSObject.Copy()
        $result.Reason = "License validation failed: $($_.Exception.Message)"
        $result.LicensePath = $LicensePath
        return $result
    }
}

function Test-CertificateIntegrity {
    <#
    .SYNOPSIS
        Verifies the HMAC-SHA256 integrity signature of an erasure certificate.

    .DESCRIPTION
        Reads an erasure certificate file, extracts the HMAC-SHA256 signature from
        the integrity signature block, recomputes the HMAC over the certificate
        content above the signature block, and compares the two values.

        The HMAC key is derived from the machine SID and the certificate ID,
        binding the certificate to the machine that generated it.

    .PARAMETER CertificatePath
        Full path to the erasure certificate text file.

    .OUTPUTS
        Hashtable with keys:
            Valid           [bool]   - Whether the HMAC signature is valid.
            CertificatePath [string] - The path that was checked.
            Message         [string] - Descriptive result message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CertificatePath
    )

    try {
        if (-not (Test-Path $CertificatePath)) {
            return @{
                Valid           = $false
                CertificatePath = $CertificatePath
                Message         = 'Certificate file not found.'
            }
        }

        $content = [System.IO.File]::ReadAllText($CertificatePath, [System.Text.Encoding]::UTF8)

        # Find the signature block marker
        $signatureMarker = '--- INTEGRITY SIGNATURE ---'
        $markerIndex = $content.IndexOf($signatureMarker)

        if ($markerIndex -lt 0) {
            return @{
                Valid           = $false
                CertificatePath = $CertificatePath
                Message         = 'No integrity signature block found in certificate.'
            }
        }

        # Extract content above the signature block (the signed payload)
        $payload = $content.Substring(0, $markerIndex)

        # Extract the recorded HMAC from the signature block
        $signatureBlock = $content.Substring($markerIndex)
        if ($signatureBlock -match 'HMAC-SHA256:\s*([0-9a-fA-F]+)') {
            $recordedHmac = $Matches[1].ToLowerInvariant()
        }
        else {
            return @{
                Valid           = $false
                CertificatePath = $CertificatePath
                Message         = 'Could not parse HMAC value from signature block.'
            }
        }

        # Extract certificate ID from the payload
        if ($payload -match 'Certificate ID:\s+([0-9a-fA-F\-]+)') {
            $certificateId = $Matches[1]
        }
        else {
            return @{
                Valid           = $false
                CertificatePath = $CertificatePath
                Message         = 'Could not extract Certificate ID from certificate content.'
            }
        }

        # Derive the HMAC key from machine SID + certificate ID
        $machineSID = (Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" |
            Select-Object -First 1).SID -replace '-\d+$'
        $keyMaterial = "$machineSID|$certificateId"
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyMaterial)

        # Compute HMAC-SHA256 over the payload
        $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $hashBytes = $hmac.ComputeHash($payloadBytes)
        $hmac.Dispose()

        $computedHmac = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''

        if ($computedHmac -eq $recordedHmac) {
            return @{
                Valid           = $true
                CertificatePath = $CertificatePath
                Message         = 'Certificate integrity verified. HMAC signature is valid.'
            }
        }
        else {
            return @{
                Valid           = $false
                CertificatePath = $CertificatePath
                Message         = 'Certificate integrity check FAILED. The certificate may have been tampered with.'
            }
        }
    }
    catch {
        return @{
            Valid           = $false
            CertificatePath = $CertificatePath
            Message         = "Integrity check error: $($_.Exception.Message)"
        }
    }
}

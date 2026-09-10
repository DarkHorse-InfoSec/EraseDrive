function New-ErasureCertificate {
    <#
    .SYNOPSIS
        Generates a data destruction certificate documenting an erasure operation.

    .DESCRIPTION
        Creates a NIST SP 800-88 Rev.1 compliant erasure certificate as a formatted
        text file. The certificate records the operator, target media, erasure method,
        verification results, and compliance information. It is saved to the directory
        specified by $Script:EraseDriveConfig.CertDirectory.

        The certificate filename follows the pattern:
            ErasureCert_<OperationType>_<yyyyMMdd_HHmmss>.txt

        This is a private helper function called after disk erase or user data wipe
        operations complete. It logs the certificate creation via Write-OperationLog.

    .PARAMETER OperationType
        The type of erasure operation performed. 'DiskErase' for full-disk overwrite
        operations, 'UserWipe' for user profile data destruction, or 'ReissueWipe' for a
        whole-device reissue wipe that leaves the operating system installed.

    .PARAMETER TargetDescription
        A human-readable description of the erasure target (e.g. "PhysicalDrive1 -
        Samsung SSD 860 EVO 500GB" or "All user profiles on C:\Users").

    .PARAMETER Method
        The erasure method applied. Expected values are 'Standard' (single-pass
        zero-fill per NIST 800-88 Clear) or 'Secure' (3-pass overwrite: zeros,
        ones, random per NIST 800-88 Clear).

    .PARAMETER DiskSerial
        Optional serial number of the target disk for audit trail purposes.

    .PARAMETER DiskModel
        Optional model identifier of the target disk.

    .PARAMETER DiskSizeGB
        Optional capacity of the target disk in gigabytes.

    .PARAMETER VerificationResult
        Optional PSCustomObject from Test-EraseVerification containing the properties:
        Verified (bool), SamplesChecked (int), SamplesPassed (int), SamplesFailed (int).
        When provided, the certificate includes detailed verification statistics.

    .PARAMETER OperatorName
        Name of the operator who performed the erasure. Defaults to the current
        Windows domain-qualified username (DOMAIN\Username).

    .PARAMETER AdditionalNotes
        Optional free-text notes to include in the certificate for supplementary
        context such as reason for destruction or asset tracking references.

    .OUTPUTS
        PSCustomObject with the following properties:
            CertificateId  - [guid]   Unique identifier for the certificate.
            FilePath       - [string] Full path to the generated .txt certificate file.
            PdfFilePath    - [string] Path to the generated .pdf cert (Pro+ tier only; $null on Free).
            Success        - [bool]   Whether the .txt certificate was written successfully.
            LicenseTier    - [string] Active license tier at generation time (Free, Pro, Team, MSP).

    .EXAMPLE
        $cert = New-ErasureCertificate -OperationType 'DiskErase' `
            -TargetDescription 'PhysicalDrive1 - Samsung SSD 860 EVO 500GB' `
            -Method 'Standard' -DiskSerial 'S3YBNX0K123456' -DiskModel 'Samsung SSD 860 EVO 500GB' `
            -DiskSizeGB 465.76

        Generates a certificate for a standard single-pass disk erase without verification.

    .EXAMPLE
        $verification = Test-EraseVerification -DiskNumber 1 -SampleCount 100
        $cert = New-ErasureCertificate -OperationType 'DiskErase' `
            -TargetDescription 'PhysicalDrive1' -Method 'Secure' `
            -VerificationResult $verification -AdditionalNotes 'Asset tag: IT-PC-0042'

        Generates a certificate for a secure 3-pass erase with verification results
        and an additional note for asset tracking.

    .EXAMPLE
        $cert = New-ErasureCertificate -OperationType 'UserWipe' `
            -TargetDescription 'All user profiles except default and system accounts' `
            -Method 'Standard'

        Generates a certificate for a user profile wipe operation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DiskErase', 'UserWipe', 'ReissueWipe')]
        [string]$OperationType,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetDescription,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Method,

        [string]$DiskSerial,

        [string]$DiskModel,

        [double]$DiskSizeGB,

        [PSCustomObject]$VerificationResult,

        [string]$OperatorName = "$env:USERDOMAIN\$env:USERNAME",

        [string]$AdditionalNotes,

        # Output of Get-DiskSanitizeCapability. Optional: when absent the
        # certificate falls back to a generic statement about Purge, because
        # saying nothing is better than implying a device-specific finding that
        # was never made.
        [PSCustomObject]$SanitizeCapability
    )

    $certId    = [guid]::NewGuid()
    $timestamp = Get-Date
    $dateStr   = $timestamp.ToString('yyyyMMdd_HHmmss')
    $utcTime   = $timestamp.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $fileName  = "ErasureCert_${OperationType}_${dateStr}.txt"
    $certDir   = $Script:EraseDriveConfig.CertDirectory
    $filePath  = Join-Path $certDir $fileName
    $pdfPath   = $null
    $version   = $Script:EraseDriveConfig.Version

    # Check active license tier. Free returns no license metadata; Pro+ unlocks the PDF.
    $licenseInfo = Test-EraseDriveLicense -Silent
    $licenseTier = $licenseInfo.Tier
    $isPaidTier  = $licenseInfo.Valid -and ($licenseTier -in @('Pro', 'Team', 'MSP'))

    Write-OperationLog -Message "Generating erasure certificate: $fileName (license tier: $licenseTier)" -LogLevel 'INFO'

    try {
        # Ensure the certificate directory exists
        if (-not (Test-Path $certDir)) {
            New-Item -Path $certDir -ItemType Directory -Force | Out-Null
        }

        $border = '=' * 80

        # Determine method description.
        #
        # These strings are a compliance claim, so each one must describe what the
        # corresponding code path actually does. Until 2026-09-09 'Standard' was
        # labelled a single-pass NIST Clear here while the code performed no pass at
        # all, and 'Secure' was labelled a NIST 3-pass when the sequence
        # zeros/ones/random is DoD 5220.22-M, which NIST superseded.
        $methodDescription = switch -Regex ($Method) {
            '^Quick'    { 'Partition removal only. NO overwrite performed. NOT a sanitization method.' }
            '^Standard' { 'NIST SP 800-88 Rev.1 Clear (single-pass zero overwrite)' }
            '^Secure'   { 'NIST SP 800-88 Rev.1 Clear (multi-pass overwrite, DoD 5220.22-M style)' }
            default     { $Method }
        }

        # A compliance claim is only made when the method sanitizes AND the result
        # was verified. Everything else states plainly what is missing.
        $isSanitizing = ($Method -notmatch '^Quick')
        $isVerified   = ($null -ne $VerificationResult -and $VerificationResult.Verified)

        $sb = [System.Text.StringBuilder]::new(4096)

        # ---- Header ----
        [void]$sb.AppendLine($border)
        [void]$sb.AppendLine('                      DATA DESTRUCTION CERTIFICATE')
        [void]$sb.AppendLine($border)
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("Certificate ID:     $certId")
        [void]$sb.AppendLine("Date of Destruction: $utcTime UTC")
        [void]$sb.AppendLine("Tool Version:       EraseDrive v$version")
        [void]$sb.AppendLine()

        # ---- Operator ----
        [void]$sb.AppendLine('--- OPERATOR ---')
        [void]$sb.AppendLine("Name:               $OperatorName")
        [void]$sb.AppendLine("Machine:            $env:COMPUTERNAME")
        [void]$sb.AppendLine()

        # ---- Target ----
        [void]$sb.AppendLine('--- TARGET ---')
        [void]$sb.AppendLine("Operation Type:     $OperationType")
        [void]$sb.AppendLine("Description:        $TargetDescription")

        if ($DiskModel) {
            [void]$sb.AppendLine("Disk Model:         $DiskModel")
        }
        if ($DiskSerial) {
            [void]$sb.AppendLine("Disk Serial:        $DiskSerial")
        }
        if ($DiskSizeGB -gt 0) {
            [void]$sb.AppendLine("Disk Size:          $([Math]::Round($DiskSizeGB, 2)) GB")
        }
        [void]$sb.AppendLine()

        # ---- Method ----
        [void]$sb.AppendLine('--- METHOD ---')
        [void]$sb.AppendLine("Erasure Method:     $Method")
        [void]$sb.AppendLine("                    $methodDescription")
        [void]$sb.AppendLine()

        # ---- Verification ----
        [void]$sb.AppendLine('--- VERIFICATION ---')

        if ($VerificationResult) {
            $vStatus = $(if ($VerificationResult.Verified) { 'PASSED' } else { 'FAILED' })
            [void]$sb.AppendLine("Status:             $vStatus")
            [void]$sb.AppendLine("Samples Checked:    $($VerificationResult.SamplesChecked)")
            [void]$sb.AppendLine("Samples Passed:     $($VerificationResult.SamplesPassed)")
            [void]$sb.AppendLine("Samples Failed:     $($VerificationResult.SamplesFailed)")
        }
        else {
            [void]$sb.AppendLine('Status:             Not performed')
        }
        [void]$sb.AppendLine()

        # ---- License ----
        [void]$sb.AppendLine('--- LICENSE ---')
        if ($isPaidTier) {
            [void]$sb.AppendLine("Tier:               $licenseTier")
            [void]$sb.AppendLine("License ID:         $($licenseInfo.LicenseId)")
            [void]$sb.AppendLine("Issued To:          $($licenseInfo.IssuedTo)")
        }
        else {
            [void]$sb.AppendLine('Tier:               Free (no license)')
            [void]$sb.AppendLine('Note:               Free tier produces .txt only. Pro license unlocks the')
            [void]$sb.AppendLine('                    signed PDF Certificate of Destruction at erasedrive.io')
        }
        [void]$sb.AppendLine()

        # ---- Compliance ----
        [void]$sb.AppendLine('--- COMPLIANCE ---')
        if (-not $isSanitizing) {
            [void]$sb.AppendLine('NO COMPLIANCE CLAIM IS MADE BY THIS CERTIFICATE.')
            [void]$sb.AppendLine('The method used removed partitioning only and did not overwrite')
            [void]$sb.AppendLine('any data. The contents of this device remain recoverable. This')
            [void]$sb.AppendLine('does not meet NIST SP 800-88 Rev.1 Clear, Purge or Destroy.')
        }
        elseif (-not $isVerified) {
            [void]$sb.AppendLine('COMPLIANCE NOT ESTABLISHED: the overwrite was performed but its')
            [void]$sb.AppendLine('result was NOT VERIFIED. NIST SP 800-88 Rev.1 section 4.7 requires')
            [void]$sb.AppendLine('verification of sanitization results, so this certificate does not')
            [void]$sb.AppendLine('assert Clear. Re-run with verification enabled before relying on')
            [void]$sb.AppendLine('this device having been sanitized.')
        }
        else {
            [void]$sb.AppendLine('This erasure meets NIST SP 800-88 Rev.1 Clear: every addressable')
            [void]$sb.AppendLine('location was overwritten and the result was verified by sampling')
            [void]$sb.AppendLine('per section 4.7.')
            [void]$sb.AppendLine()

            # Purge is a separate claim from Clear and must never be implied by
            # it. Every branch below states explicitly that Purge was NOT
            # performed, because this tool does not yet issue a sanitize command.
            if ($null -eq $SanitizeCapability) {
                [void]$sb.AppendLine('PURGE: not performed, and this device''s capability was not queried.')
                [void]$sb.AppendLine('For SSD Purge-level assurance, the drive vendor''s own sanitize or')
                [void]$sb.AppendLine('cryptographic-erase command is required in addition to this process.')
            }
            elseif ($null -eq $SanitizeCapability.PurgeCapable) {
                [void]$sb.AppendLine('PURGE: not performed. This device''s Purge capability is UNKNOWN;')
                [void]$sb.AppendLine('it could not be determined, which is NOT the same as absent. No')
                [void]$sb.AppendLine('claim is made either way.')
                if ($SanitizeCapability.Blockers) {
                    foreach ($blocker in $SanitizeCapability.Blockers) {
                        [void]$sb.AppendLine("  Reason: $blocker")
                    }
                }
            }
            elseif ($SanitizeCapability.PurgeCapable) {
                [void]$sb.AppendLine('PURGE: AVAILABLE ON THIS DEVICE BUT NOT PERFORMED.')
                [void]$sb.AppendLine('The device reports support for:')
                foreach ($method in $SanitizeCapability.PurgeMethods) {
                    [void]$sb.AppendLine("  - $method")
                }
                [void]$sb.AppendLine('Reaching NIST SP 800-88 Rev.1 Purge requires issuing one of those')
                [void]$sb.AppendLine('commands. This tool does not issue them, so Purge was NOT achieved.')
                [void]$sb.AppendLine('On flash media, overwriting cannot reach Purge at any number of')
                [void]$sb.AppendLine('passes: the flash translation layer keeps over-provisioned, retired')
                [void]$sb.AppendLine('and un-erased blocks outside the addressable LBA range.')
                foreach ($blocker in $SanitizeCapability.Blockers) {
                    [void]$sb.AppendLine("  Note: $blocker")
                }
            }
            else {
                [void]$sb.AppendLine('PURGE: not available on this device, and not performed.')
                foreach ($blocker in $SanitizeCapability.Blockers) {
                    [void]$sb.AppendLine("  Reason: $blocker")
                }
                if ($SanitizeCapability.DeviceAnswered) {
                    [void]$sb.AppendLine('  The device was queried and reported no command reaching Purge.')
                }
            }
        }
        [void]$sb.AppendLine()

        # ---- Additional Notes ----
        [void]$sb.AppendLine('--- ADDITIONAL NOTES ---')
        if ($AdditionalNotes) {
            [void]$sb.AppendLine($AdditionalNotes)
        }
        [void]$sb.AppendLine()

        # ---- Disclaimer ----
        [void]$sb.AppendLine('--- DISCLAIMER ---')
        [void]$sb.AppendLine('This certificate documents the data destruction process performed')
        [void]$sb.AppendLine('by the EraseDrive tool. The operator is responsible for verifying')
        [void]$sb.AppendLine('the completeness and adequacy of the destruction for their')
        [void]$sb.AppendLine('compliance requirements.')
        [void]$sb.AppendLine($border)

        # ---- HMAC Integrity Signature ----
        # The certificate content above the signature block is the signed payload
        $certPayload = $sb.ToString()

        # Derive HMAC key from machine SID + certificate ID
        $machineSID = (Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" |
            Select-Object -First 1).SID -replace '-\d+$'
        $keyMaterial = "$machineSID|$certId"
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyMaterial)

        # Compute HMAC-SHA256
        $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($certPayload)
        $hashBytes = $hmac.ComputeHash($payloadBytes)
        $hmac.Dispose()

        $hmacHex = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''

        # Append signature block to certificate content
        [void]$sb.AppendLine('--- INTEGRITY SIGNATURE ---')
        [void]$sb.AppendLine("HMAC-SHA256: $hmacHex")
        [void]$sb.AppendLine('Key Source:  Machine-bound (SID + CertificateId)')
        [void]$sb.AppendLine('Tampering with this certificate will invalidate the signature.')

        # Write the certificate file
        [System.IO.File]::WriteAllText($filePath, $sb.ToString(), [System.Text.Encoding]::UTF8)

        # Write the .sig file alongside the certificate
        $sigFilePath = [System.IO.Path]::ChangeExtension($filePath, '.sig')
        [System.IO.File]::WriteAllText($sigFilePath, $hmacHex, [System.Text.Encoding]::UTF8)

        Write-OperationLog -Message "Erasure certificate saved: $filePath (ID: $certId)" -LogLevel 'SUCCESS'
        Write-OperationLog -Message "Certificate signature file saved: $sigFilePath" -LogLevel 'INFO'

        # ---- PDF rendering (Pro+ license only) ----
        if ($isPaidTier) {
            try {
                $pdfPath = [System.IO.Path]::ChangeExtension($filePath, '.pdf')
                $pdfResult = New-PdfCertificate `
                    -OutPath          $pdfPath `
                    -CertificateId    $certId `
                    -Timestamp        $timestamp `
                    -OperationType    $OperationType `
                    -TargetDescription $TargetDescription `
                    -Method           $Method `
                    -MethodDescription $methodDescription `
                    -DiskSerial       $DiskSerial `
                    -DiskModel        $DiskModel `
                    -DiskSizeGB       $DiskSizeGB `
                    -VerificationResult $VerificationResult `
                    -OperatorName     $OperatorName `
                    -MachineName      $env:COMPUTERNAME `
                    -ToolVersion      $version `
                    -HmacHex          $hmacHex `
                    -LicenseTier      $licenseTier `
                    -LicenseId        $licenseInfo.LicenseId `
                    -LicenseIssuedTo  $licenseInfo.IssuedTo

                if ($pdfResult.Success) {
                    Write-OperationLog -Message "PDF certificate saved: $($pdfResult.FilePath)" -LogLevel 'SUCCESS'
                }
                else {
                    Write-OperationLog -Message "PDF certificate generation failed: $($pdfResult.Message)" -LogLevel 'WARNING'
                    $pdfPath = $null
                }
            }
            catch {
                Write-OperationLog -Message "PDF certificate generation error: $($_.Exception.Message)" -LogLevel 'WARNING'
                $pdfPath = $null
            }
        }

        return [PSCustomObject]@{
            CertificateId = $certId
            FilePath      = $filePath
            PdfFilePath   = $pdfPath
            Success       = $true
            LicenseTier   = $licenseTier
        }
    }
    catch {
        $errMsg = "Failed to generate erasure certificate: $_"
        Write-OperationLog -Message $errMsg -LogLevel 'ERROR'

        return [PSCustomObject]@{
            CertificateId = $certId
            FilePath      = $null
            PdfFilePath   = $null
            Success       = $false
            LicenseTier   = $licenseTier
        }
    }
}

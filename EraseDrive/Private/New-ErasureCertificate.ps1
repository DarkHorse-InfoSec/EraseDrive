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
        The type of erasure operation performed. Must be 'DiskErase' for full-disk
        overwrite operations or 'UserWipe' for user profile data destruction.

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
            FilePath       - [string] Full path to the generated certificate file.
            Success        - [bool]   Whether the certificate was written successfully.

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
        [ValidateSet('DiskErase', 'UserWipe')]
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

        [string]$AdditionalNotes
    )

    $certId    = [guid]::NewGuid()
    $timestamp = Get-Date
    $dateStr   = $timestamp.ToString('yyyyMMdd_HHmmss')
    $utcTime   = $timestamp.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $fileName  = "ErasureCert_${OperationType}_${dateStr}.txt"
    $certDir   = $Script:EraseDriveConfig.CertDirectory
    $filePath  = Join-Path $certDir $fileName
    $version   = $Script:EraseDriveConfig.Version

    Write-OperationLog -Message "Generating erasure certificate: $fileName" -LogLevel 'INFO'

    try {
        # Ensure the certificate directory exists
        if (-not (Test-Path $certDir)) {
            New-Item -Path $certDir -ItemType Directory -Force | Out-Null
        }

        $border = '=' * 80

        # Determine method description
        $methodDescription = switch ($Method) {
            'Standard' { 'NIST 800-88 Clear (single pass)' }
            'Secure'   { 'NIST 800-88 Clear (3-pass: zeros, ones, random)' }
            default    { $Method }
        }

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

        # ---- Compliance ----
        [void]$sb.AppendLine('--- COMPLIANCE ---')
        [void]$sb.AppendLine('This erasure follows NIST SP 800-88 Rev.1 Clear guidelines.')
        [void]$sb.AppendLine('For SSD Purge-level assurance, manufacturer-specific tools')
        [void]$sb.AppendLine('are recommended in addition to this process.')
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

        return [PSCustomObject]@{
            CertificateId = $certId
            FilePath      = $filePath
            Success       = $true
        }
    }
    catch {
        $errMsg = "Failed to generate erasure certificate: $_"
        Write-OperationLog -Message $errMsg -LogLevel 'ERROR'

        return [PSCustomObject]@{
            CertificateId = $certId
            FilePath      = $null
            Success       = $false
        }
    }
}

function New-PdfCertificate {
    <#
    .SYNOPSIS
        Generates a single-page Certificate of Destruction PDF.

    .DESCRIPTION
        Writes a hand-crafted PDF (PDF 1.4, Letter size) containing the destruction
        certificate fields. Uses only the PDF base-14 fonts (Helvetica, Helvetica-Bold,
        Courier) so no font embedding is required and the file renders identically in
        Adobe Reader, Chrome, Foxit, and SumatraPDF.

        The PDF is a customer-facing rendering. The HMAC-SHA256 line shown in the footer
        is the same HMAC computed by New-ErasureCertificate over the .txt content; both
        files reference the same Certificate ID so an auditor checking either lands on
        the same proof.

        This function is called only when a Pro+ license is active. Free tier writes only
        the .txt certificate.

    .PARAMETER OutPath
        Path where the .pdf file will be written.

    .PARAMETER CertificateId
        GUID identifying this certificate (matches the companion .txt cert).

    .PARAMETER Timestamp
        Operation timestamp.

    .PARAMETER OperationType
        DiskErase or UserWipe.

    .PARAMETER TargetDescription
        Human-readable target description.

    .PARAMETER Method
        Method label (Standard / Secure / Secure (Clear-Disk + 3-pass overwrite) / ...).

    .PARAMETER MethodDescription
        Longer prose describing the method.

    .PARAMETER DiskSerial
        Disk serial number, if applicable.

    .PARAMETER DiskModel
        Disk model, if applicable.

    .PARAMETER DiskSizeGB
        Disk size in GB, if applicable.

    .PARAMETER VerificationResult
        Optional verification PSCustomObject (Verified, SamplesChecked, SamplesPassed, SamplesFailed).

    .PARAMETER OperatorName
        Operator (domain-qualified Windows user).

    .PARAMETER MachineName
        Machine where the wipe ran.

    .PARAMETER ToolVersion
        EraseDrive version string.

    .PARAMETER HmacHex
        Hex-encoded HMAC-SHA256 over the .txt cert payload.

    .PARAMETER LicenseTier
        Pro, Team, or MSP.

    .PARAMETER LicenseId
        License identifier from the .lic file.

    .PARAMETER LicenseIssuedTo
        Customer name from the .lic file.

    .OUTPUTS
        PSCustomObject:
            Success    [bool]
            FilePath   [string]
            Message    [string]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$OutPath,
        [Parameter(Mandatory)] [guid]$CertificateId,
        [Parameter(Mandatory)] [datetime]$Timestamp,
        [Parameter(Mandatory)] [string]$OperationType,
        [Parameter(Mandatory)] [string]$TargetDescription,
        [Parameter(Mandatory)] [string]$Method,
        [Parameter(Mandatory)] [string]$MethodDescription,
        [string]$DiskSerial,
        [string]$DiskModel,
        [double]$DiskSizeGB,
        [PSCustomObject]$VerificationResult,
        [Parameter(Mandatory)] [string]$OperatorName,
        [Parameter(Mandatory)] [string]$MachineName,
        [Parameter(Mandatory)] [string]$ToolVersion,
        [Parameter(Mandatory)] [string]$HmacHex,
        [Parameter(Mandatory)] [ValidateSet('Pro', 'Team', 'MSP')] [string]$LicenseTier,
        [Parameter(Mandatory)] [string]$LicenseId,
        [Parameter(Mandatory)] [string]$LicenseIssuedTo
    )

    # ── Sanitize: escape PDF string metacharacters and drop non-ASCII ────
    $escString = {
        param([string]$s)
        if ($null -eq $s) { return '' }
        $s = [string]$s
        $sb = [System.Text.StringBuilder]::new($s.Length + 4)
        foreach ($ch in $s.ToCharArray()) {
            $code = [int]$ch
            if ($code -lt 32 -or $code -gt 126) {
                [void]$sb.Append('?')
            }
            elseif ($ch -eq '(' -or $ch -eq ')' -or $ch -eq '\') {
                [void]$sb.Append('\').Append($ch)
            }
            else {
                [void]$sb.Append($ch)
            }
        }
        return $sb.ToString()
    }

    # Page geometry (US Letter, 1 pt = 1/72 inch)
    $pageWidth = 612
    $pageHeight = 792
    $marginLeft = 54
    $marginRight = 558
    $contentWidth = $marginRight - $marginLeft

    # Approximate Helvetica avg-char widths as a fraction of em
    $charWidthFactor = @{ F1 = 0.50; F2 = 0.55; F3 = 0.60 }

    # ── Build the line model ─────────────────────────────────────────────
    $L = New-Object 'System.Collections.Generic.List[hashtable]'

    $addLine = {
        param(
            [string]$Text,
            [string]$Font = 'F1',
            [int]$Size = 10,
            [string]$Align = 'L',
            [double]$Leading = 14
        )
        $L.Add(@{ T = $Text; F = $Font; S = $Size; A = $Align; LD = $Leading })
    }

    # Header block
    & $addLine -Text 'CERTIFICATE OF DATA DESTRUCTION' -Font 'F2' -Size 18 -Align 'C' -Leading 22
    & $addLine -Text $(
        if ($Method -match '^Quick') { 'NOT A SANITIZATION. NO COMPLIANCE CLAIM.' }
        elseif ($null -ne $VerificationResult -and $VerificationResult.Verified) { 'NIST SP 800-88 Rev. 1 Compliant' }
        else { 'NIST SP 800-88 Rev. 1 COMPLIANCE NOT ESTABLISHED' }
    ) -Font 'F1' -Size 11 -Align 'C' -Leading 18
    & $addLine -Text ''

    # Identifiers
    & $addLine -Text ("Certificate ID:    {0}" -f $CertificateId)                                       -Font 'F1' -Size 10
    & $addLine -Text ("Issued (UTC):      {0} UTC" -f $Timestamp.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) -Font 'F1' -Size 10
    & $addLine -Text ("Tool:              EraseDrive v{0}" -f $ToolVersion)                            -Font 'F1' -Size 10
    & $addLine -Text ''

    # Operator
    & $addLine -Text 'OPERATOR' -Font 'F2' -Size 11 -Leading 16
    & $addLine -Text ("Name:              {0}" -f $OperatorName) -Font 'F1' -Size 10
    & $addLine -Text ("Workstation:       {0}" -f $MachineName)  -Font 'F1' -Size 10
    & $addLine -Text ''

    # Target
    & $addLine -Text 'TARGET MEDIA' -Font 'F2' -Size 11 -Leading 16
    & $addLine -Text ("Operation:         {0}" -f $OperationType)      -Font 'F1' -Size 10
    & $addLine -Text ("Description:       {0}" -f $TargetDescription)  -Font 'F1' -Size 10
    if ($DiskModel) {
        & $addLine -Text ("Disk Model:        {0}" -f $DiskModel)  -Font 'F1' -Size 10
    }
    if ($DiskSerial) {
        & $addLine -Text ("Serial Number:     {0}" -f $DiskSerial) -Font 'F1' -Size 10
    }
    if ($DiskSizeGB -gt 0) {
        & $addLine -Text ("Capacity:          {0} GB" -f ([Math]::Round($DiskSizeGB, 2))) -Font 'F1' -Size 10
    }
    & $addLine -Text ''

    # Method
    & $addLine -Text 'ERASURE METHOD' -Font 'F2' -Size 11 -Leading 16
    & $addLine -Text ("Method:            {0}" -f $Method)            -Font 'F1' -Size 10
    & $addLine -Text ("Description:       {0}" -f $MethodDescription) -Font 'F1' -Size 10
    # The reference must track what ran. A method that overwrites nothing gets no
    # NIST reference at all, and an unverified overwrite does not assert Clear,
    # because Rev.1 section 4.7 makes verification part of the standard.
    $pdfVerified = ($null -ne $VerificationResult -and $VerificationResult.Verified)
    $nistRef = if ($Method -match '^Quick') {
        'NONE. Partition removal only; not a NIST SP 800-88 sanitization.'
    } elseif (-not $pdfVerified) {
        'NIST SP 800-88 Rev. 1 Section 2.4 (Clear) NOT ESTABLISHED: result unverified'
    } elseif ($Method -match 'Secure') {
        'NIST SP 800-88 Rev. 1, Section 2.4 (Clear); multi-pass overwrite, verified'
    } else {
        'NIST SP 800-88 Rev. 1, Section 2.4 (Clear); single-pass overwrite, verified'
    }
    & $addLine -Text ("NIST Reference:    {0}" -f $nistRef) -Font 'F1' -Size 10
    & $addLine -Text ''

    # Verification
    & $addLine -Text 'VERIFICATION' -Font 'F2' -Size 11 -Leading 16
    if ($VerificationResult) {
        $vStatus = if ($VerificationResult.Verified) { 'PASSED' } else { 'FAILED' }
        & $addLine -Text ("Status:            {0}" -f $vStatus) -Font 'F1' -Size 10
        & $addLine -Text ("Samples Checked:   {0}" -f $VerificationResult.SamplesChecked) -Font 'F1' -Size 10
        & $addLine -Text ("Samples Passed:    {0}" -f $VerificationResult.SamplesPassed) -Font 'F1' -Size 10
        & $addLine -Text ("Samples Failed:    {0}" -f $VerificationResult.SamplesFailed) -Font 'F1' -Size 10
    } else {
        & $addLine -Text 'Status:            Not performed' -Font 'F1' -Size 10
    }
    & $addLine -Text ''

    # License
    & $addLine -Text 'LICENSE' -Font 'F2' -Size 11 -Leading 16
    & $addLine -Text ("Issued To:         {0}" -f $LicenseIssuedTo) -Font 'F1' -Size 10
    & $addLine -Text ("License ID:        {0}" -f $LicenseId)       -Font 'F1' -Size 10
    & $addLine -Text ("Tier:              {0}" -f $LicenseTier)     -Font 'F1' -Size 10
    & $addLine -Text ''

    # Compliance statement
    & $addLine -Text 'COMPLIANCE STATEMENT' -Font 'F2' -Size 11 -Leading 16
    & $addLine -Text 'This certificate documents the data destruction process performed by'  -Font 'F1' -Size 10
    & $addLine -Text 'the EraseDrive tool in accordance with NIST SP 800-88 Rev. 1 media'    -Font 'F1' -Size 10
    & $addLine -Text 'sanitization guidelines. The operator named above is responsible for'  -Font 'F1' -Size 10
    & $addLine -Text 'verifying the completeness and adequacy of the destruction for their'  -Font 'F1' -Size 10
    & $addLine -Text 'specific compliance requirements.'                                     -Font 'F1' -Size 10
    & $addLine -Text ''

    # Integrity
    & $addLine -Text 'INTEGRITY' -Font 'F2' -Size 11 -Leading 16
    & $addLine -Text ("HMAC-SHA256: {0}" -f $HmacHex)                       -Font 'F3' -Size 8 -Leading 12
    & $addLine -Text 'Key Source:  Machine-bound (SID + Certificate ID)'   -Font 'F1' -Size 10

    # Footer (positioned at fixed Y near bottom; rendered separately)

    # ── Render content stream ────────────────────────────────────────────
    $stream = [System.Text.StringBuilder]::new(4096)
    $y = $pageHeight - 54  # top margin = 54

    foreach ($ln in $L) {
        $text = & $escString $ln.T
        $font = $ln.F
        $size = $ln.S
        $align = $ln.A
        $leading = $ln.LD

        if ($text -ne '') {
            # Compute X position based on alignment
            $cwFactor = $charWidthFactor[$font]
            $approxWidth = $text.Length * $size * $cwFactor

            switch ($align) {
                'C' {
                    $x = ($pageWidth - $approxWidth) / 2
                    if ($x -lt $marginLeft) { $x = $marginLeft }
                }
                'R' {
                    $x = $marginRight - $approxWidth
                    if ($x -lt $marginLeft) { $x = $marginLeft }
                }
                default { $x = $marginLeft }
            }

            [void]$stream.Append('BT ').Append('/').Append($font).Append(' ').Append($size).Append(' Tf ')
            [void]$stream.Append('1 0 0 1 ').Append([string]([Math]::Round($x, 2))).Append(' ').Append([string]([Math]::Round($y, 2))).Append(' Tm ')
            [void]$stream.Append('(').Append($text).Append(') Tj ')
            [void]$stream.AppendLine('ET')
        }

        $y -= $leading
    }

    # Footer: bottom of page, centered, small grey
    $footerText = & $escString ("EraseDrive v{0}   erasedrive.io   Document: {1}" -f $ToolVersion, $CertificateId.ToString())
    $footerSize = 8
    $footerY = 40
    $footerWidth = $footerText.Length * $footerSize * 0.50
    $footerX = ($pageWidth - $footerWidth) / 2
    if ($footerX -lt $marginLeft) { $footerX = $marginLeft }

    [void]$stream.Append('BT /F1 ').Append($footerSize).Append(' Tf ')
    [void]$stream.Append('1 0 0 1 ').Append([string]([Math]::Round($footerX, 2))).Append(' ').Append($footerY).Append(' Tm ')
    [void]$stream.Append('(').Append($footerText).Append(') Tj ')
    [void]$stream.AppendLine('ET')

    $contentStream = $stream.ToString()
    $contentBytes = [System.Text.Encoding]::ASCII.GetBytes($contentStream)
    $contentLength = $contentBytes.Length

    # ── Build PDF objects ────────────────────────────────────────────────
    # Object numbering:
    #   1 - Catalog
    #   2 - Pages
    #   3 - Page
    #   4 - Page Contents
    #   5 - Font F1 (Helvetica)
    #   6 - Font F2 (Helvetica-Bold)
    #   7 - Font F3 (Courier)
    #   8 - Info

    $produced = "EraseDrive {0} ({1})" -f $ToolVersion, $LicenseId
    $infoTitle = & $escString "EraseDrive Certificate of Destruction"
    $infoAuthor = & $escString $OperatorName
    $infoSubject = & $escString ("Certificate ID {0}; HMAC {1}" -f $CertificateId, $HmacHex)
    $infoProducer = & $escString $produced
    $infoDate = "D:" + $Timestamp.ToUniversalTime().ToString('yyyyMMddHHmmss') + "Z"

    $objects = @(
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        ("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {0} {1}] /Resources << /Font << /F1 5 0 R /F2 6 0 R /F3 7 0 R >> >> /Contents 4 0 R >>" -f $pageWidth, $pageHeight),
        ("<< /Length {0} >>`nstream`n{1}endstream" -f $contentLength, $contentStream),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
        ("<< /Title ({0}) /Author ({1}) /Subject ({2}) /Producer ({3}) /Creator (EraseDrive) /CreationDate ({4}) >>" -f $infoTitle, $infoAuthor, $infoSubject, $infoProducer, $infoDate)
    )

    # ── Assemble PDF byte stream and track object offsets ───────────────
    # Use ASCII encoding throughout; we sanitized all strings to ASCII.
    $outBuf = New-Object 'System.Collections.Generic.List[byte]'
    $appendAscii = {
        param([string]$s)
        $b = [System.Text.Encoding]::ASCII.GetBytes($s)
        $outBuf.AddRange($b)
    }

    # PDF header
    & $appendAscii "%PDF-1.4`n"
    # Per PDF spec, recommended to include a binary marker line so file is recognized as binary
    $outBuf.AddRange([byte[]]@(0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A))

    $offsets = New-Object 'System.Collections.Generic.List[int]'
    $offsets.Add(0)  # placeholder for object 0 (free entry)

    for ($i = 0; $i -lt $objects.Count; $i++) {
        $offsets.Add($outBuf.Count)
        & $appendAscii ("{0} 0 obj`n{1}`nendobj`n" -f ($i + 1), $objects[$i])
    }

    # Cross-reference table
    $xrefOffset = $outBuf.Count
    & $appendAscii "xref`n"
    & $appendAscii ("0 {0}`n" -f ($objects.Count + 1))
    & $appendAscii "0000000000 65535 f `n"
    for ($i = 1; $i -le $objects.Count; $i++) {
        & $appendAscii ("{0:D10} 00000 n `n" -f $offsets[$i])
    }

    # Trailer
    & $appendAscii ("trailer`n<< /Size {0} /Root 1 0 R /Info 8 0 R >>`nstartxref`n{1}`n%%EOF`n" -f ($objects.Count + 1), $xrefOffset)

    # ── Write file ───────────────────────────────────────────────────────
    try {
        $outDir = Split-Path $OutPath -Parent
        if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
            New-Item -Path $outDir -ItemType Directory -Force | Out-Null
        }
        [System.IO.File]::WriteAllBytes($OutPath, $outBuf.ToArray())

        return [PSCustomObject]@{
            Success  = $true
            FilePath = $OutPath
            Message  = "PDF certificate written to $OutPath"
        }
    }
    catch {
        return [PSCustomObject]@{
            Success  = $false
            FilePath = $null
            Message  = "Failed to write PDF certificate: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Runs every EraseDrive Pester suite, one at a time, and summarises the result.

.DESCRIPTION
    Two constraints make `Invoke-Pester -Path .\Tests\` the wrong way to run this
    project's tests, and both were learned the hard way:

    1. THE SUITES CANNOT RUN CONCURRENTLY, and pointing Pester at the Tests
       directory runs them in a single invocation that shares one process.
       `Enter-OperationLock` takes a SYSTEM-WIDE named mutex, so the second suite
       to reach it fails with "Another EraseDrive operation is already running"
       and then produces a scatter of unrelated assertion failures that look like
       real regressions. This script runs each suite in its own Invoke-Pester
       call, sequentially.

    2. THE PESTER VERSION MUST BE PINNED. The module manifest targets Windows
       PowerShell 5.1 and Pester 5.x. Some machines in this fleet (DES-70072)
       also carry Pester 6.1.0, which is a higher version and therefore wins by
       default, and its configuration surface differs. This script imports
       5.7.1 explicitly and prints which version it actually loaded.

    Failures are written to one file per suite so a long run can be read after
    the fact rather than scrolled back through.

.PARAMETER OutputDirectory
    Where the summary and per-suite failure detail are written.
    Defaults to a timestamped directory under the user's TEMP.

.PARAMETER PesterVersion
    The Pester version to pin. Defaults to 5.7.1.

.EXAMPLE
    .\tools\Invoke-AllSuites.ps1

.NOTES
    Exits non-zero if any suite has a failing test, so it is safe to gate on.

    Do not trust a single timing from this script. The same commit has been
    measured at 364s, 493s and 1381s for EraseDrive.Tests.ps1 on one machine.
    Take at least three timings before attributing a difference to anything.
#>
[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [string] $PesterVersion = '5.7.1'
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$testsDir = Join-Path $repoRoot 'Tests'

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $env:TEMP ("EraseDrive-tests-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
$summaryPath = Join-Path $OutputDirectory 'SUITE-SUMMARY.txt'

Import-Module Pester -RequiredVersion $PesterVersion -Force
$loaded = (Get-Module Pester).Version
"Pester in use : $loaded"          | Tee-Object -FilePath $summaryPath
"Repository    : $repoRoot"        | Tee-Object -FilePath $summaryPath -Append
"Output        : $OutputDirectory" | Tee-Object -FilePath $summaryPath -Append
''                                 | Tee-Object -FilePath $summaryPath -Append

# Ordered cheapest first, so a broad breakage surfaces in seconds rather than
# after the slow suite has run.
$suites = @(
    'SafetyGuards.Tests.ps1'
    'License.Tests.ps1'
    'PdfCertificate.Tests.ps1'
    'ReissueWipe.Tests.ps1'
    'SanitizeCapability.Tests.ps1'
    'SanitizationContract.Tests.ps1'
    'ReformatAfterErase.Tests.ps1'
    'EraseDrive.Tests.ps1'
)

$totalFailed = 0
$totalPassed = 0
$runStopwatch = [Diagnostics.Stopwatch]::StartNew()

foreach ($suite in $suites) {
    $suitePath = Join-Path $testsDir $suite
    if (-not (Test-Path -LiteralPath $suitePath)) {
        "SKIP  $suite (not present)" | Tee-Object -FilePath $summaryPath -Append
        continue
    }

    $config = New-PesterConfiguration
    $config.Run.Path            = $suitePath
    $config.Run.PassThru        = $true
    $config.Output.Verbosity    = 'None'
    $config.Should.ErrorAction  = 'Continue'

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-Pester -Configuration $config
    $sw.Stop()

    $totalFailed += $result.FailedCount
    $totalPassed += $result.PassedCount

    $line = '{0,-34} P={1,-5} F={2,-5} S={3,-5} T={4,-5} {5,8:N1}s' -f `
            $suite, $result.PassedCount, $result.FailedCount,
            $result.SkippedCount, $result.TotalCount, $sw.Elapsed.TotalSeconds
    $line | Tee-Object -FilePath $summaryPath -Append

    if ($result.FailedCount -gt 0) {
        $detailPath = Join-Path $OutputDirectory ('FAIL-' + $suite.Replace('.Tests.ps1', '') + '.txt')
        $result.Failed | ForEach-Object {
            "### $($_.ExpandedPath)"
            "    $($_.ErrorRecord.Exception.Message)"
            '    ' + (($_.ErrorRecord.ScriptStackTrace -split "`n" | Select-Object -First 2) -join "`n    ")
            ''
        } | Set-Content -LiteralPath $detailPath -Encoding UTF8
        "      -> $detailPath" | Tee-Object -FilePath $summaryPath -Append
    }
}

$runStopwatch.Stop()
'' | Tee-Object -FilePath $summaryPath -Append
"TOTAL passed  : $totalPassed"  | Tee-Object -FilePath $summaryPath -Append
"TOTAL failed  : $totalFailed"  | Tee-Object -FilePath $summaryPath -Append
"Elapsed       : $([math]::Round($runStopwatch.Elapsed.TotalSeconds, 1))s" | Tee-Object -FilePath $summaryPath -Append

if ($totalFailed -gt 0) {
    Write-Host "$totalFailed failing test(s). Detail in $OutputDirectory" -ForegroundColor Red
    exit 1
}

Write-Host "All suites passed ($totalPassed tests)." -ForegroundColor Green

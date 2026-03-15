function Write-OperationLog {
    <#
    .SYNOPSIS
        Writes a timestamped log entry to the EraseDrive log file and console.

    .DESCRIPTION
        Logs operational messages to the centralized EraseDrive log file located
        in ProgramData (NOT the Desktop, which would be destroyed during a wipe).
        Implements automatic log rotation when the log file exceeds the configured
        maximum size, retaining up to MaxLogFiles historical copies.

        Console output is color-coded by log level for quick visual identification.
        This function never throws exceptions - all failures are silently caught to
        ensure logging issues never interrupt critical erase operations.

    .PARAMETER Message
        The message text to write to the log.

    .PARAMETER LogLevel
        The severity level of the log entry. Valid values: INFO, SUCCESS, WARNING, ERROR.
        Defaults to INFO.

    .EXAMPLE
        Write-OperationLog -Message 'Disk 1 erase started' -LogLevel 'INFO'

    .EXAMPLE
        Write-OperationLog -Message 'Erase complete with verification' -LogLevel 'SUCCESS'

    .EXAMPLE
        Write-OperationLog -Message 'Disk health degraded' -LogLevel 'WARNING'

    .OUTPUTS
        None. Writes to log file and console as side effects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$LogLevel = 'INFO'
    )

    try {
        # Build the log entry
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logEntry = "$timestamp [$LogLevel] $Message"

        # Resolve log file path from module config
        $logFile = $Script:EraseDriveConfig.LogFile
        $logDir = $Script:EraseDriveConfig.LogDirectory
        $maxSizeMB = $Script:EraseDriveConfig.MaxLogSizeMB
        $maxFiles = $Script:EraseDriveConfig.MaxLogFiles

        # Ensure log directory exists
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }

        # Rotate logs if file exceeds maximum size
        if (Test-Path $logFile) {
            $fileSizeMB = (Get-Item $logFile).Length / 1MB
            if ($fileSizeMB -ge $maxSizeMB) {
                # Shift existing rotated logs up by one (.4 -> .5, .3 -> .4, etc.)
                for ($i = $maxFiles; $i -ge 1; $i--) {
                    $source = $(if ($i -eq 1) { $logFile } else { "$logFile.$($i - 1)" })
                    $destination = "$logFile.$i"

                    if (Test-Path $source) {
                        if ($i -eq $maxFiles) {
                            # Remove the oldest log if we've hit the cap
                            Remove-Item $destination -Force -ErrorAction SilentlyContinue
                        }
                        Move-Item -Path $source -Destination $destination -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        # Write the log entry
        Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue

        # Console output with color coding
        $color = switch ($LogLevel) {
            'SUCCESS' { 'Green' }
            'WARNING' { 'Yellow' }
            'ERROR'   { 'Red' }
            default   { 'White' }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
    catch {
        # Never throw on log failure - logging must not disrupt operations
    }
}

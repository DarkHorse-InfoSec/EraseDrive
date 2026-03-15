function Write-AuditLog {
    <#
    .SYNOPSIS
        Writes an audit log entry to both the operation log and Windows Application Event Log.

    .DESCRIPTION
        Provides a tamper-resistant audit trail by writing structured log entries to the
        Windows Application Event Log (which survives disk wipe operations) in addition
        to the standard operation log file. This ensures compliance-grade audit records
        persist even when the target disk or log files are destroyed during erasure.

        Event IDs follow a structured scheme:
        - 1000: OperationStarted
        - 1001: OperationCompleted
        - 1002: OperationFailed
        - 1003: SafetyAbort
        - 1004: CertificateGenerated

        If the Windows Event Log source cannot be registered or written to (e.g.,
        insufficient privileges), the function falls back silently to Write-OperationLog
        only. This function never throws exceptions.

    .PARAMETER EventType
        The type of event being logged. Must be one of: OperationStarted,
        OperationCompleted, OperationFailed, SafetyAbort, CertificateGenerated.

    .PARAMETER Message
        Detailed message describing the event.

    .PARAMETER OperatorName
        The identity of the operator performing the action. Defaults to the current
        Windows user identity.

    .PARAMETER TargetDescription
        Optional description of the target (e.g., disk number, profile name).

    .EXAMPLE
        Write-AuditLog -EventType 'OperationStarted' -Message 'Secure disk erase initiated' -TargetDescription 'Disk 2'

    .EXAMPLE
        Write-AuditLog -EventType 'OperationFailed' -Message 'Erase failed: disk removed during operation'

    .OUTPUTS
        None. Writes to Windows Event Log and operation log as side effects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('OperationStarted', 'OperationCompleted', 'OperationFailed', 'SafetyAbort', 'CertificateGenerated')]
        [string]$EventType,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$OperatorName = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name),

        [string]$TargetDescription
    )

    # Map event types to event IDs
    $eventIdMap = @{
        'OperationStarted'    = 1000
        'OperationCompleted'  = 1001
        'OperationFailed'     = 1002
        'SafetyAbort'         = 1003
        'CertificateGenerated' = 1004
    }

    $eventId = $eventIdMap[$EventType]

    # Build structured message
    $structuredMessage = "EventType: $EventType | Operator: $OperatorName | Target: $TargetDescription | Detail: $Message"

    # Always write to the operation log
    $logLevel = switch ($EventType) {
        'OperationStarted'     { 'INFO' }
        'OperationCompleted'   { 'SUCCESS' }
        'OperationFailed'      { 'ERROR' }
        'SafetyAbort'          { 'WARNING' }
        'CertificateGenerated' { 'SUCCESS' }
    }

    Write-OperationLog -Message $structuredMessage -LogLevel $logLevel

    # Attempt to write to Windows Application Event Log
    try {
        # Register the event source if not already registered
        New-EventLog -LogName Application -Source 'EraseDrive' -ErrorAction SilentlyContinue

        Write-EventLog -LogName Application -Source 'EraseDrive' -EventId $eventId -EntryType Information -Message $structuredMessage
    }
    catch {
        # Fall back silently - the operation log entry above is sufficient
    }
}

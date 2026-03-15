function Exit-OperationLock {
    <#
    .SYNOPSIS
        Releases and disposes the system-wide EraseDrive operation mutex.

    .DESCRIPTION
        Releases the mutex previously acquired by Enter-OperationLock and disposes
        the underlying handle. Errors are silently handled to ensure cleanup never
        interrupts critical operations.

    .PARAMETER Mutex
        The System.Threading.Mutex object returned by Enter-OperationLock.

    .OUTPUTS
        None.
    #>
    [CmdletBinding()]
    param(
        [System.Threading.Mutex]$Mutex
    )

    try {
        if ($Mutex) {
            $Mutex.ReleaseMutex()
            $Mutex.Dispose()
            Write-OperationLog -Message 'Operation lock released.' -LogLevel 'INFO'
        }
    }
    catch {
        # Silently handle errors - lock cleanup must not disrupt operations
        try {
            Write-OperationLog -Message "Error releasing operation lock: $($_.Exception.Message)" -LogLevel 'WARNING'
        }
        catch { }
    }
}

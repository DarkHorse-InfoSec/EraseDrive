function Enter-OperationLock {
    <#
    .SYNOPSIS
        Acquires a system-wide mutex to prevent concurrent EraseDrive operations.

    .DESCRIPTION
        Creates a named system mutex (Global\EraseDrive_OperationLock) and attempts
        a non-blocking acquisition. Returns a hashtable indicating whether the lock
        was acquired and, if so, the mutex object for later release.

    .PARAMETER OperationName
        A descriptive name for the operation requesting the lock. Used in log messages.
        Default: 'EraseDrive'

    .OUTPUTS
        Hashtable with keys:
            Acquired [bool]   - Whether the lock was successfully acquired.
            Mutex    [Mutex]  - The mutex object (only present when Acquired is $true).
            Message  [string] - Descriptive message (only present when Acquired is $false).
    #>
    [CmdletBinding()]
    param(
        [string]$OperationName = 'EraseDrive'
    )

    try {
        $mutexName = 'Global\EraseDrive_OperationLock'
        $mutex = [System.Threading.Mutex]::new($false, $mutexName)

        $acquired = $mutex.WaitOne(0)

        if (-not $acquired) {
            Write-OperationLog -Message "Operation lock not acquired for '$OperationName' - another EraseDrive operation is already running." -LogLevel 'WARNING'
            $mutex.Dispose()
            return @{
                Acquired = $false
                Message  = 'Another EraseDrive operation is already running.'
            }
        }

        Write-OperationLog -Message "Operation lock acquired for '$OperationName'." -LogLevel 'INFO'
        return @{
            Acquired = $true
            Mutex    = $mutex
        }
    }
    catch {
        Write-OperationLog -Message "Failed to acquire operation lock: $($_.Exception.Message)" -LogLevel 'WARNING'
        return @{
            Acquired = $false
            Message  = "Failed to acquire operation lock: $($_.Exception.Message)"
        }
    }
}

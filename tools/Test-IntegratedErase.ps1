# Prove the INTEGRATED Invoke-SecureDiskErase -Reformat path end to end, against a
# real disk device, in about a minute rather than 89.
#
# A VHD attached through diskpart presents as a genuine physical disk: it gets a
# disk number, a \\.\PhysicalDriveN path, and real Get-Disk / Clear-Disk /
# New-Partition / Format-Volume behaviour. Everything the erase does is exercised
# for real. The only thing it does not reproduce is the physical media behaviour of
# the SanDisk, which the 88-minute run on 2026-09-09 already covered.
#
# It also reproduces the condition that broke the reformat: zeroing the whole
# device zeroes sector 0, which is what makes Windows invent a phantom layout.

$SIZE_MB   = 2048
$VHD       = Join-Path $env:TEMP 'erasedrive-integration-test.vhd'
$ResultPath    = 'C:\Users\dlaur\AppData\Local\Temp\erasedrive-integration-result.txt'
$SENTINEL  = 'C:\Users\dlaur\AppData\Local\Temp\erasedrive-integration-DONE.txt'

$TRANSCRIPT = 'C:\Users\dlaur\AppData\Local\Temp\erasedrive-integration-transcript.txt'
Remove-Item $ResultPath, $SENTINEL, $TRANSCRIPT -Force -ErrorAction SilentlyContinue
try { Start-Transcript -Path $TRANSCRIPT -Force | Out-Null } catch { }
$log = New-Object System.Collections.Generic.List[string]
function Say([string]$m) { $log.Add($m); Write-Host $m }

$attachedDisk = $null

function Invoke-DiskPart([string[]]$Commands) {
    $f = Join-Path $env:TEMP ("edvhd_" + [guid]::NewGuid().ToString('N') + ".txt")
    $Commands | Set-Content -Path $f -Encoding ASCII -Force
    $out = & diskpart /s $f 2>&1
    $code = $LASTEXITCODE
    Remove-Item $f -Force -ErrorAction SilentlyContinue
    [PSCustomObject]@{ ExitCode = $code; Output = ($out -join "`n") }
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'not elevated' }
    Say "Identity : $($id.Name)  (elevated)"

    # Record the real disks BEFORE attaching, so the new one can be identified by
    # difference rather than by guessing a number.
    $before = @(Get-Disk | Select-Object -ExpandProperty Number)
    Say "Existing disks: $($before -join ', ')"

    Remove-Item $VHD -Force -ErrorAction SilentlyContinue
    Say ""
    Say "Creating and attaching a ${SIZE_MB} MB VHD at $VHD"
    $r = Invoke-DiskPart @(
        "create vdisk file=`"$VHD`" maximum=$SIZE_MB type=fixed"
        "select vdisk file=`"$VHD`""
        'attach vdisk'
    )
    if ($r.ExitCode -ne 0) { throw "diskpart could not create/attach the VHD (exit $($r.ExitCode)): $($r.Output)" }
    Start-Sleep -Seconds 2
    Update-HostStorageCache -ErrorAction SilentlyContinue

    $after = @(Get-Disk | Select-Object -ExpandProperty Number)
    $new = @($after | Where-Object { $_ -notin $before })
    if ($new.Count -ne 1) { throw "expected exactly one new disk after attaching, saw $($new.Count): $($new -join ', ')" }
    $attachedDisk = [int]$new[0]
    Say "Attached as disk $attachedDisk"

    # ---- Gate hard. This must never be able to select a real disk. ----
    $d = Get-Disk -Number $attachedDisk -ErrorAction Stop
    $sizeGB = [math]::Round($d.Size / 1GB, 2)
    Say ""
    Say "Target gate:"
    Say ("  FriendlyName : {0}" -f $d.FriendlyName)
    Say ("  Size         : {0} GB" -f $sizeGB)
    Say ("  BusType      : {0}" -f $d.BusType)
    Say ("  IsBoot/System: {0} / {1}" -f $d.IsBoot, $d.IsSystem)

    if ($d.IsBoot -or $d.IsSystem) { throw 'gate: reports boot or system' }
    if ($sizeGB -gt 4) { throw "gate: $sizeGB GB is far larger than the ${SIZE_MB} MB VHD; refusing" }
    if ($d.FriendlyName -notmatch 'Virtual') { throw "gate: FriendlyName '$($d.FriendlyName)' does not look like a virtual disk" }
    if ($attachedDisk -in $before) { throw 'gate: the selected disk existed before attach' }
    Say "  gate passed: this is the VHD, not a real disk."

    Import-Module 'D:\Projects\Open-Source\EraseDrive-gh\EraseDrive' -Force -ErrorAction Stop

    Say ""
    Say "=== RUNNING THE REAL THING ==="
    Say "Invoke-SecureDiskErase -DiskNumber $attachedDisk -EraseMethod Standard -Reformat"
    Say ""
    $started = Get-Date
    $result = Invoke-SecureDiskErase -DiskNumber $attachedDisk -EraseMethod Standard `
        -Reformat -ReformatLabel 'INTEGRATION' -Confirm:$false

    Say ("=== RESULT ({0:N1}s) ===" -f ((Get-Date) - $started).TotalSeconds)
    foreach ($prop in $result.PSObject.Properties) { Say ("  {0,-19}: {1}" -f $prop.Name, $prop.Value) }

    Say ""
    Say "=== POST-STATE, read back independently ==="
    Update-HostStorageCache -ErrorAction SilentlyContinue
    $d2 = Get-Disk -Number $attachedDisk -ErrorAction SilentlyContinue
    Say ("  PartitionStyle : {0}" -f $d2.PartitionStyle)
    foreach ($pt in (Get-Partition -DiskNumber $attachedDisk -ErrorAction SilentlyContinue)) {
        Say ("  partition {0}: size={1} GB letter='{2}'" -f $pt.PartitionNumber, [math]::Round($pt.Size/1GB,2), $pt.DriveLetter)
        if ($pt.DriveLetter) {
            $v = Get-Volume -DriveLetter $pt.DriveLetter -ErrorAction SilentlyContinue
            if ($v) { Say ("    volume: label='{0}' fs={1} free={2} GB health={3}" -f $v.FileSystemLabel, $v.FileSystem, [math]::Round($v.SizeRemaining/1GB,2), $v.HealthStatus) }
            # Prove it is genuinely usable.
            $probe = "$($pt.DriveLetter):\.integration_check"
            try {
                Set-Content -LiteralPath $probe -Value 'usable' -ErrorAction Stop
                $back = (Get-Content -LiteralPath $probe -Raw -ErrorAction Stop).Trim()
                Remove-Item -LiteralPath $probe -Force -ErrorAction Stop
                Say "    read/write check: wrote and read back '$back'"
            }
            catch { Say "    read/write check FAILED: $($_.Exception.Message)" }
        }
    }

    Say ""
    Say "=== CERTIFICATE ==="
    if ($result.CertificatePath -and (Test-Path $result.CertificatePath)) {
        $show = $false
        foreach ($line in (Get-Content -LiteralPath $result.CertificatePath)) {
            if ($line -match '^--- (METHOD|VERIFICATION|COMPLIANCE) ---') { $show = $true }
            elseif ($line -match '^--- ') { $show = $false }
            if ($show) { Say ("  " + $line) }
        }
    }
    else { Say "  certificate MISSING" }
}
catch {
    Say ""
    Say "EXCEPTION: $($_.Exception.Message)"
}
finally {
    # ---- Always detach and delete the VHD ----
    try {
        Say ""
        Say "Cleaning up the VHD..."
        $r2 = Invoke-DiskPart @("select vdisk file=`"$VHD`"", 'detach vdisk')
        Say "  detach exit code: $($r2.ExitCode)"
        Start-Sleep -Seconds 1
        Remove-Item $VHD -Force -ErrorAction SilentlyContinue
        if (Test-Path $VHD) { Say "  WARNING: $VHD still present" } else { Say "  VHD file removed." }
    }
    catch { Say "  cleanup problem: $($_.Exception.Message)" }

    # Write the result without depending on the pipeline: an empty or awkward $log
    # must not be the reason the run leaves no trace, which is what happened on the
    # first attempt.
    try {
        [System.IO.File]::WriteAllLines($ResultPath, [string[]]$log.ToArray())
    }
    catch {
        try { "result-write failed: $($_.Exception.Message)" | Out-File -FilePath $ResultPath -Encoding utf8 -Force } catch { }
    }
    try { Stop-Transcript | Out-Null } catch { }
    'done' | Out-File -FilePath $SENTINEL -Encoding utf8 -Force
}

# ---------------------------------------------------------------------------
# Kept in the repo deliberately. This is the cheapest honest end-to-end test of
# Invoke-SecureDiskErase that exists: it exercises the real code against a real
# disk device in about seven seconds, needs no disposable hardware, and leaves
# nothing behind. Run it elevated after any change to the erase or reformat path.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\Test-IntegratedErase.ps1
#
# It cannot select a real disk: the attached VHD is identified by set-difference
# against the disks present beforehand, and then gated on size, FriendlyName and
# the boot/system flags.
# ---------------------------------------------------------------------------

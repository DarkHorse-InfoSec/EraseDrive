# EraseDrive - Forensic Disk & Data Destruction Module

A professional PowerShell module for secure data destruction on Windows systems. Features SSD-aware erasure, multi-pass overwrite, post-erase verification, and tamper-evident erasure certificates.

## CRITICAL WARNING

**This tool permanently destroys data. There is no undo.** Always ensure important data is backed up before proceeding with any wipe operation. Verify you are selecting the correct target before executing.

## What's New in v3.0

- **Proper PowerShell module** - Replaces the monolithic `erase_drive.ps1` with a structured `EraseDrive` module (manifest, public/private functions, Pester tests)
- **CLI automation mode** - Run unattended disk erasure and user wipes via `Start-EraseDrive.ps1 -Mode CLI` for MDT/SCCM integration
- **SSD-aware erasure** - Detects NVMe and SATA SSDs; reports ATA Secure Erase and NVMe Format availability
- **Post-erase verification** - Random sector sampling confirms the disk was fully overwritten
- **Erasure certificates** - Generates a signed text certificate for each operation with a unique ID, timestamp, operator, method, and verification result
- **Centralized logging** - Logs to `%ProgramData%\DarkHorse\EraseDrive\` with automatic rotation (not the Desktop, which would be destroyed during a wipe)
- **Windows Event Log audit trail** - Critical operations are dual-written to the Application Event Log (source: EraseDrive), surviving even file-level log deletion
- **HMAC-signed certificates** - Erasure certificates include an HMAC-SHA256 integrity signature tied to the machine, with `Test-CertificateIntegrity` for tamper verification
- **Operation locking** - System-wide named mutex prevents concurrent erase operations
- **Disk identity pinning** - Captures disk serial number before erasure and re-verifies before each destructive step to prevent hot-plug race conditions
- **Scaled verification** - Sector sample count scales with disk size (100 to 10,000 samples) with unique offset deduplication
- **Operation timeout** - `-TimeoutMinutes` parameter for automated environments; generates partial certificate on timeout
- **-Force flag for automation** - Bypasses ShouldProcess confirmation for MDT/SCCM task sequences
- **RAID/Storage Spaces detection** - Blocks erasure of disks participating in storage pools or RAID arrays
- **Background operation support** - GUI operations run asynchronously and report progress
- **TRIM detection** - Identifies drives with TRIM support for informed erasure decisions

## Features

- **Forensic User Data Wipe** - Removes all user profiles, browser data, caches, and forensic artifacts while keeping the system bootable
- **Complete Disk Erasure** - Securely wipes entire non-system disks with multi-pass overwrite
- **Multiple Safety Layers** - Automatic system/boot disk detection, partition analysis, and multi-step confirmation
- **Visual Safety Indicators** - Color-coded disk status in the GUI (Blue = system, Green = safe, Pink = unsafe, White = empty)
- **Erasure Certificates** - Generates a unique certificate for every operation for audit and compliance
- **Post-Erase Verification** - Samples random sectors to confirm successful overwrite
- **SSD Detection** - Identifies media type, protocol (NVMe/SATA/SAS/USB), and secure erase capabilities
- **GUI + CLI** - Interactive graphical interface or fully scriptable command-line mode

## System Requirements

| Requirement | Detail |
|---|---|
| **OS** | Windows 10/11 or Windows Server 2016+ |
| **PowerShell** | 5.1 or higher |
| **Privileges** | Administrator (elevated) |
| **.NET Framework** | 4.5+ (pre-installed on modern Windows) |
| **Pester** (tests only) | 5.x |

## Module Structure

```
erase-drive/
├── Start-EraseDrive.ps1              # Entry point: GUI + CLI launcher
├── EraseDrive/
│   ├── EraseDrive.psd1               # Module manifest
│   ├── EraseDrive.psm1               # Module loader (dot-sources Private/ and Public/)
│   ├── Public/
│   │   ├── Invoke-ForensicUserDataWipe.ps1   # Forensic user data wipe
│   │   ├── Invoke-SecureDiskErase.ps1        # Complete disk erasure
│   │   └── Start-EraseDriveGUI.ps1           # WinForms GUI
│   └── Private/
│       ├── Write-OperationLog.ps1            # Centralized logging with rotation
│       ├── Write-AuditLog.ps1               # Windows Event Log audit trail
│       ├── Test-DiskSafeToErase.ps1          # Safety checks (RAID, virtual disk, offline)
│       ├── Update-DiskList.ps1               # GUI DataTable population
│       ├── Get-DiskMediaType.ps1             # SSD/HDD/NVMe detection
│       ├── Invoke-SecureOverwrite.ps1        # Multi-pass overwrite engine
│       ├── Test-EraseVerification.ps1        # Scaled random sector verification
│       ├── New-ErasureCertificate.ps1        # HMAC-signed certificate generation
│       ├── Test-CertificateIntegrity.ps1     # Certificate tamper detection
│       ├── Enter-OperationLock.ps1           # Mutex lock acquisition
│       └── Exit-OperationLock.ps1            # Mutex lock release
├── Tests/
│   └── EraseDrive.Tests.ps1          # Pester 5.x test suite
├── README.md
├── logo.png
└── logo.ico
```

## Installation

1. Clone or copy the `erase-drive/` folder to your target machine.
2. Ensure PowerShell execution policy allows script execution:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. **If you downloaded a ZIP from GitHub**, Windows marks every extracted file as
   coming from the internet (Mark-of-the-Web / Zone.Identifier ADS). Even with
   `RemoteSigned`, unsigned downloaded scripts are blocked. Unblock the folder
   recursively after extracting:
   ```powershell
   Get-ChildItem -Path .\EraseDrive-main -Recurse | Unblock-File
   ```
   Alternatively, launch a single session with `-ExecutionPolicy Bypass`:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Start-EraseDrive.ps1
   ```
4. No additional modules are required. The module self-loads from `Start-EraseDrive.ps1`.

To import the module directly in your own scripts (from the extracted folder):
```powershell
Import-Module .\EraseDrive -Force
```

### Optional: Install as a user/system module

If you'd rather invoke EraseDrive cmdlets from anywhere instead of running
`Start-EraseDrive.ps1` from the extracted folder, copy the `EraseDrive/` module
folder into a directory on `$env:PSModulePath`:

```powershell
# Current user (recommended, no admin elevation required for copy step)
$dest = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Modules\EraseDrive'
Copy-Item -Path .\EraseDrive -Destination $dest -Recurse -Force

# All users (requires elevated PowerShell)
Copy-Item -Path .\EraseDrive -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\EraseDrive" -Recurse -Force
```

After this, `Import-Module EraseDrive` works from any directory, and the
public cmdlets (`Invoke-ForensicUserDataWipe`, `Invoke-SecureDiskErase`,
`Start-EraseDriveGUI`) are available globally.

## Usage: GUI Mode

Launch the graphical interface (default):

```powershell
# Right-click PowerShell, select "Run as Administrator"
.\Start-EraseDrive.ps1
```

### GUI Workflow

1. **Review disk list** - System disks are marked blue; safe disks are green
2. **Check** "I have backed up important data"
3. **Select** wipe method (Standard or Secure)
4. **Choose operation** - "Forensic User Wipe" or "Erase Disk"
5. **Type confirmation text** exactly as shown (e.g., `WIPE USERS` or `ERASE`)
6. **Wait** for completion; progress is reported in real time

### Disk Safety Status Colors

| Color | Meaning |
|---|---|
| Blue | System disk, user data wipe only |
| Green | Safe for complete erasure |
| Pink | Unsafe, contains system components |
| White | No data / unpartitioned |

## Usage: CLI Mode

Run headless for automation, scripting, and MDT/SCCM task sequences.

### Forensic User Data Wipe

```powershell
# Standard wipe (fast)
.\Start-EraseDrive.ps1 -Mode CLI -Operation UserWipe -Method Standard -Confirm

# Secure wipe with event log clearing
.\Start-EraseDrive.ps1 -Mode CLI -Operation UserWipe -Method Secure -ClearEventLogs -Confirm
```

### Complete Disk Erasure

```powershell
# Interactive erase with confirmation prompt
.\Start-EraseDrive.ps1 -Mode CLI -Operation DiskErase -DiskNumber 2 -Method Secure

# Automated erase (no confirmation prompt, for MDT/SCCM)
.\Start-EraseDrive.ps1 -Mode CLI -Operation DiskErase -DiskNumber 2 -Method Secure -Force

# With timeout (abort after 120 minutes)
.\Start-EraseDrive.ps1 -Mode CLI -Operation DiskErase -DiskNumber 2 -Method Secure -Force -TimeoutMinutes 120

# Quick erase, skip verification
.\Start-EraseDrive.ps1 -Mode CLI -Operation DiskErase -DiskNumber 1 -Method Standard -SkipVerification -Force
```

### Using the Module Directly

```powershell
Import-Module .\EraseDrive -Force

# Forensic user data wipe
$result = Invoke-ForensicUserDataWipe -WipeMethod Secure -ClearEventLogs
$result | Format-List

# Complete disk erasure
$result = Invoke-SecureDiskErase -DiskNumber 2 -EraseMethod Secure
$result | Format-List

# Check if a disk is safe (private function; use InModuleScope or call via module)
```

### MDT / SCCM Task Sequence Integration

Add a "Run PowerShell Script" step:

```
Script: Start-EraseDrive.ps1
Parameters: -Mode CLI -Operation DiskErase -DiskNumber 1 -Method Secure -Force -TimeoutMinutes 120
```

The `-Force` flag suppresses interactive confirmation prompts. The script returns exit code `0` on success and `1` on failure, compatible with task sequence error handling.

## Operations

### Forensic User Data Wipe

Removes all user forensic artifacts while keeping the system bootable.

**What it removes:**
- All user profiles (Desktop, Documents, Downloads, Pictures, Videos, Music)
- Browser data (Chrome, Edge, Firefox: history, cookies, cache, bookmarks)
- Application data (AppData Local/Roaming)
- Temporary files (system and user)
- User registry hives
- Prefetch files and download caches
- Error reporting data
- Windows Event Logs (optional, off by default)

**What it preserves:**
- Windows operating system
- Installed programs
- System files and boot capability

### Complete Disk Erasure

Securely wipes entire non-system disks.

**What it does:**
- Clears all partitions and volume data
- Overwrites entire disk surface (Secure method)
- Verifies overwrite success via random sector sampling
- Generates an erasure certificate

## Wipe Methods

### Standard Method
- **Speed:** Fast (5-15 minutes typical)
- **Process:** Removes partition tables and file allocation data
- **Use case:** Regular data destruction, preparing drives for reuse
- **Note:** Data may be recoverable with specialized forensic tools

### Secure Method (Multi-Pass Overwrite)
- **Speed:** Slower (30-120+ minutes depending on disk size)
- **Process:** Three-pass overwrite: zeros (0x00), ones (0xFF), cryptographic random data
- **Use case:** Sensitive data, compliance requirements, end-of-life disposal
- **Note:** Significantly reduces forensic recovery possibilities for HDDs

## SSD Support

EraseDrive detects SSD media type and protocol automatically:

| Protocol | Secure Erase Support | Recommended Method |
|---|---|---|
| NVMe SSD | NVMe Format (cryptographic erase) | Manufacturer tools for Purge-level |
| SATA SSD | ATA Secure Erase | Manufacturer tools for Purge-level |
| HDD (SATA/SAS) | Multi-pass overwrite | EraseDrive Secure method |
| USB drives | Multi-pass overwrite | EraseDrive Secure method |

> **Important:** For SSDs, multi-pass overwrite addresses accessible storage areas but may not reach over-provisioned or wear-leveled blocks. For NIST 800-88 Purge-level destruction on SSDs, use manufacturer-provided secure erase utilities (e.g., Samsung Magician, Intel SSD Toolbox, or the drive's ATA Secure Erase / NVMe Format command).

## Post-Erase Verification

After a Secure erase, EraseDrive performs a verification pass:

1. Opens the physical disk in read mode
2. Calculates sample count based on disk size: `max(100, min(10000, diskSizeGB x 10))`
   - 100 GB disk: 1,000 samples
   - 500 GB disk: 5,000 samples
   - 1 TB+ disk: 10,000 samples (cap)
3. Generates cryptographically random, unique sector offsets (no duplicate sampling)
4. Reads each 512-byte sector and compares against expected post-erase pattern (0x00)
5. Reports pass/fail count, failed sector offsets, and coverage percentage

Verification results are included in the erasure certificate. Use `-SkipVerification` to bypass (not recommended).

## Erasure Certificates

Every successful operation generates an HMAC-signed, tamper-evident text certificate stored in:

```
%ProgramData%\DarkHorse\EraseDrive\Certificates\
```

Each certificate includes:
- **Unique Certificate ID** (GUID-based)
- **Timestamp** (UTC)
- **Operator** (logged-in user and machine name)
- **Operation type** (DiskErase or UserWipe)
- **Target description** (disk model, serial number, size)
- **Erasure method** (Standard or Secure with pass count)
- **Verification result** (pass/fail, sample count)
- **Module version**
- **HMAC-SHA256 integrity signature** (machine-bound, tamper-evident)

Each certificate also has a companion `.sig` file containing the raw HMAC hash. To verify a certificate hasn't been tampered with:

```powershell
Import-Module .\EraseDrive -Force
# Access the private function via module scope
& (Get-Module EraseDrive) { Test-CertificateIntegrity -CertificatePath 'C:\ProgramData\DarkHorse\EraseDrive\Certificates\ErasureCert_DiskErase_20260315_143022.txt' }
```

Certificates provide documentation for compliance audits and chain-of-custody records.

## Security & Compliance

### Compliance Statement

Implements multi-pass overwrite following **NIST 800-88 Clear** guidelines. The Secure method performs a three-pass overwrite (zeros, ones, random) which meets the Clear media sanitization standard for HDDs.

**For NIST 800-88 Purge on SSDs, use manufacturer tools.** EraseDrive's software-based overwrite cannot guarantee sanitization of SSD over-provisioned areas, wear-leveled blocks, or controller-managed spare sectors. Use ATA Secure Erase, NVMe Format, or cryptographic erase commands provided by the drive manufacturer.

This tool is suitable for:
- **NIST 800-88 Clear** - HDD multi-pass overwrite (Secure method)
- **GDPR Article 17** - Right to erasure / data destruction
- **Corporate data destruction policies** - With certificate documentation
- **Forensic investigation cleanup** - User data artifact removal

### Data Recovery Considerations

| Method | HDD Recovery Risk | SSD Recovery Risk |
|---|---|---|
| Standard | Possible with forensic tools | Possible (TRIM may help) |
| Secure | Very low for accessible areas | Low for accessible areas; over-provisioned blocks may retain data |
| Physical destruction | None | None |

### Safety Features

- Automatic system/boot disk detection
- System, Reserved, and Recovery partition blocking
- Windows installation and Program Files path detection
- RAID / Storage Spaces membership detection
- Virtual disk and offline disk detection
- Disk identity pinning (serial number verified before each destructive step)
- System-wide mutex lock (prevents concurrent operations)
- Large disk (>2 TB) advisory warning
- Multi-step confirmation (checkbox + typed confirmation + dialog)
- Dual logging: file-based with rotation + Windows Application Event Log
- Operation timeout support for automated environments

## Running Tests

```powershell
# Install Pester 5.x (if not already installed)
Install-Module -Name Pester -MinimumVersion 5.0.0 -Force -SkipPublisherCheck

# Run the full test suite
Invoke-Pester -Path .\Tests\EraseDrive.Tests.ps1 -Output Detailed

# Run with code coverage
Invoke-Pester -Path .\Tests\EraseDrive.Tests.ps1 -Output Detailed -CodeCoverage .\EraseDrive\**\*.ps1
```

## Troubleshooting

### "Cannot find type [System.Windows.Forms.Button]"
Run as Administrator. The .NET Framework WinForms assembly requires elevation on some systems.

### "Execution Policy" Error / "File is not digitally signed"

The script files extracted from a GitHub ZIP carry a Mark-of-the-Web zone
identifier that blocks them under `RemoteSigned` even after you change the
execution policy. You have two options:

1. **Unblock the files** (preferred, one-time fix):
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   Get-ChildItem -Path .\EraseDrive-main -Recurse | Unblock-File
   ```

2. **Bypass the policy for a single invocation**:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File .\Start-EraseDrive.ps1
   ```

If you cloned with `git clone` rather than downloading a ZIP, the MOTW marker
is not applied and `RemoteSigned` alone is sufficient.

### "No suitable disks found"
Normal if you only have one system disk. The system disk appears in blue and supports user data wipe only.

### Disk Not Appearing
1. Click **Refresh List** in the GUI
2. Verify the disk is recognized in Windows Disk Management (`diskmgmt.msc`)
3. Check that the disk is online and initialized

### Log File Location
Logs are stored in `%ProgramData%\DarkHorse\EraseDrive\EraseDrive.log` with automatic rotation at 10 MB (up to 5 historical files).

## Version History

### v3.0.0 (Current)
- Complete module restructure (Public/Private function split)
- CLI automation mode with `-Force` flag for MDT/SCCM
- SSD-aware media type and protocol detection
- Real multi-pass secure overwrite (NIST 800-88 Clear)
- Scaled post-erase verification (100-10,000 samples based on disk size)
- HMAC-signed erasure certificates with tamper detection
- System-wide mutex lock preventing concurrent operations
- Disk identity pinning (serial verification before destructive steps)
- RAID / Storage Spaces / virtual disk safety detection
- Windows Event Log audit trail (dual-write logging)
- Operation timeout support (`-TimeoutMinutes`)
- Centralized logging with rotation (moved from Desktop to ProgramData)
- TRIM detection
- Pester 5.x test suite
- WhatIf/ShouldProcess support on destructive commands

### v2.0
- Added forensic user data wipe functionality
- Enhanced safety features for system disk protection
- Color-coded visual indicators
- Comprehensive logging
- Multiple confirmation steps
- Standard and Secure wipe methods

### v1.0
- Basic disk erasing functionality
- Simple GUI interface
- Administrator privilege checking

## Legal Notice

This tool is provided as-is for legitimate data destruction purposes. Users are responsible for:

- Ensuring legal right to destroy the target data
- Compliance with organizational policies and regulations
- Proper backup of important information before use
- Understanding that these operations are **permanent and irreversible**
- Selecting appropriate sanitization methods for their compliance requirements

**DarkHorse InfoSec assumes no liability for data loss resulting from the use of this tool.**

---

**DarkHorse InfoSec** - EraseDrive v3.0.0

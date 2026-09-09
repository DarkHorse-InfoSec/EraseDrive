# EraseDrive - Forensic Disk & Data Destruction Module

A professional PowerShell module for secure data destruction on Windows systems. Features SSD-aware erasure, multi-pass overwrite, post-erase verification, and tamper-evident erasure certificates.

## CRITICAL WARNING

**This tool permanently destroys data. There is no undo.** Always ensure important data is backed up before proceeding with any wipe operation. Verify you are selecting the correct target before executing.

## Pricing (v3.1)

EraseDrive is freemium. The wipe is always free. The signed PDF Certificate of Destruction requires a paid license.

| Tier | Price       | Includes |
|------|-------------|----------|
| Free | $0          | Unlimited wipes. Text (.txt) certificate with HMAC-SHA256 integrity signature. |
| Pro  | $99 once    | Lifetime. Signed PDF Certificate of Destruction. All future versions. |
| Team | $499 / yr   | 5 technicians (honor system). All Pro features. |
| MSP  | $1499 / yr  | Unlimited technicians, multi-tenant. All Team features. |

Buy at [erasedrive.io](https://erasedrive.io) or directly via Gumroad. The license file is emailed within 24 hours of purchase.

**Activating a license:**

1. Save the `license.lic` you received to `%ProgramData%\DarkHorse\EraseDrive\license.lic`. You may need to create the folder if EraseDrive has never been run on this machine.
2. (Or, in the GUI) click "LOAD LICENSE" and select your `.lic` file.
3. The header badge changes from `TIER: FREE` to `TIER: PRO` (or Team / MSP). Future wipes generate both `.txt` and `.pdf` certificates.

EraseDrive does not phone home. License validation is entirely offline: the `.lic` is RSA-signed by DarkHorse InfoSec and verified locally against an embedded public key. Safe to run on air-gapped networks.

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

### Device Reissue Wipe

> **Not available in v3.1.0.** The reissue wipe and the WinPE boot-media builder
> ship in this release but are deliberately **not exported**, because neither has
> been executed against a real machine yet. They become public API in v3.2 once
> the offline wipe is proven end to end. Documented here so the design is
> reviewable; the commands below will not resolve in v3.1.0.

```powershell
# Offline, from the WinPE boot stick. The complete wipe.
.\Start-EraseDrive.ps1 -Mode CLI -Operation ReissueWipe -OfflineRoot C:\ -RemoveFromDomain -Method Secure -Force

# Live, with sysprep, ready to hand over
.\Start-EraseDrive.ps1 -Mode CLI -Operation ReissueWipe -RemoveFromDomain -Generalize -Force
```

Exit codes: `0` wipe complete, `2` succeeded but remnants remain (see the printed list),
`1` failed. A partial wipe never exits `0`.

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

# Erase, then bring the disk back as a usable NTFS volume instead of leaving it raw
.\Start-EraseDrive.ps1 -Mode CLI -Operation DiskErase -DiskNumber 2 -Method Secure -Force -Reformat

# Same, as exFAT for a removable stick that has to work outside Windows
.\Start-EraseDrive.ps1 -Mode CLI -Operation DiskErase -DiskNumber 2 -Method Secure -Force `
    -Reformat -ReformatFileSystem exFAT -ReformatLabel RECOVERED
```

### Erase methods, and what each one actually does

| Method | What it does | Compliance |
|---|---|---|
| `Quick` | Removes the partition table. **Writes nothing.** Data stays on the media and is recoverable with ordinary tools. | **None claimed.** Not a sanitization. |
| `Standard` **(default)** | Removes the partition table, then overwrites every addressable sector once with zeros. | NIST SP 800-88 Rev.1 **Clear**, once verified. |
| `Secure` | Media-aware: multi-pass overwrite on rotational media, full-device zero fill (`diskpart clean all`) on SSDs. | NIST SP 800-88 Rev.1 **Clear**, once verified. |

Two things worth being clear about, because the industry is usually not:

**`Secure` is not more NIST-compliant than `Standard`.** Both reach Clear. NIST
SP 800-88 Rev.1 Appendix A states that a single overwrite pass with a fixed
pattern hinders recovery even against laboratory techniques; the multi-pass
zeros/ones/random sequence is DoD 5220.22-M, which NIST superseded. `Secure`
exists because procurement and audit checklists still ask for it.

**Neither reaches Purge on an SSD.** Purge needs the drive's own sanitize or
cryptographic-erase command. Overwriting an SSD cannot reach over-provisioned or
wear-levelled blocks. The certificate says so rather than implying otherwise.

**Verification is part of the standard, not an extra.** Section 4.7 of
SP 800-88 Rev.1 requires that sanitization results be verified, so EraseDrive
samples sectors afterwards and checks them against the byte the erase actually
wrote. **A certificate only asserts NIST Clear when that verification passed.**
If the overwrite ran but was not confirmed, the certificate says
`COMPLIANCE NOT ESTABLISHED`; if `Quick` was used, it says
`NO COMPLIANCE CLAIM IS MADE BY THIS CERTIFICATE`.

### After an erase, the disk is RAW. That is normal.

Erasing removes the partition table along with the data, so a successfully erased
disk has no filesystem and no drive letter, and will not appear in File Explorer.
It is not damaged. This is the correct end state for a destruction tool: the
default leaves nothing behind to be recovered from.

To get a usable disk back, either:

- pass `-Reformat` (CLI) or tick **Reformat disk after erase** (GUI), or
- open Disk Management (`diskmgmt.msc`), right-click the disk, choose
  **Initialize Disk**, then create a **New Simple Volume**.

`-Reformat` is off by default and is deliberately gated. It runs only after the
erase *and* its verification have both succeeded, so a filesystem is never written
over a disk EraseDrive has not confirmed to be clean; doing that would bury any
residual data under a fresh directory structure and make a later audit harder. It
is skipped, with the reason reported in `ReformatMessage`, when `-SkipVerification`
was used, when verification did not pass, or when the requested filesystem cannot
address the disk (FAT32 above 32 GB, MBR above 2 TB).

A failed reformat never fails the erase. The data is destroyed and the certificate
is valid either way; the disk is simply still raw. When a reformat does happen, the
erasure certificate records it, so an auditor who finds a live filesystem on a
"destroyed" disk can see that EraseDrive put it there and when.

### Using the Module Directly

```powershell
Import-Module .\EraseDrive -Force

# Forensic user data wipe
$result = Invoke-ForensicUserDataWipe -WipeMethod Secure -ClearEventLogs
$result | Format-List

# Complete disk erasure
$result = Invoke-SecureDiskErase -DiskNumber 2 -EraseMethod Secure
$result | Format-List

# Erase, verify, then reformat so the disk is usable again
$result = Invoke-SecureDiskErase -DiskNumber 2 -EraseMethod Secure -Reformat
$result.Reformatted      # $true if a filesystem was created
$result.DriveLetter      # the letter it was mounted as
$result.ReformatMessage  # what happened, or why it was skipped

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

### Device Reissue Wipe

Returns a device to a clean state so it can be handed to a different employee or sold,
with Windows still installed. This is the operation to use when the business has finished
with a machine.

Run it two ways, and the difference is not cosmetic:

| | Offline (recommended) | Live |
|---|---|---|
| How | Boot the EraseDrive WinPE stick, pass `-OfflineRoot` | Run against the running Windows |
| Every user profile removable | Yes | No, the operator's own survives |
| Cached domain credentials (`HKLM\SECURITY`) | Yes | Only if running as SYSTEM |
| `pagefile.sys` / `hiberfil.sys` | Deleted | Scheduled for clearing on shutdown |
| Can be complete | Yes | No |

A live wipe is convenient and is structurally incapable of being complete. It reports every
remnant it could not remove in `Unreachable` rather than glossing over them, and the CLI
exits `2` rather than `0` when the wipe succeeded but left remnants behind.

**What it removes:**
- All user profiles, their registry hives, and their ProfileList records
- Cached domain logon verifiers (`NL$1`..`NL$10`) and the `NL$KM` key that decrypts them
- Machine-wide Credential Manager vaults and Windows Hello / NGC containers
- Volume Shadow Copies and System Restore points, which otherwise still hold the deleted data
- `pagefile.sys`, `hiberfil.sys` and `swapfile.sys`
- The Recycle Bin on every volume, not just the system volume
- Saved wireless profiles, the NetworkList history, VPN phonebooks, network printers, proxy
  and hosts entries
- USB device history (USBSTOR, MountedDevices), Windows Timeline, `Windows.old`, Windows
  Update and Delivery Optimization caches, cached Group Policy
- Domain membership and the machine account secret, with `-RemoveFromDomain`

**What it preserves:**
- Windows, installed programs, and boot capability
- **Active Directory. Nothing in this tool writes to the directory.** `-RemoveFromDomain`
  removes the *device* from the domain. User accounts are untouched, so a departing user
  signs in on their next machine exactly as before, and the computer object is left in
  place for your normal stale-object cleanup.

**Optional `-Generalize`** runs `sysprep /generalize /oobe` afterwards so the device boots
to out-of-box setup like a new machine. It is opt-in because it consumes one of a limited
number of rearms, requires the machine to be unjoined first, and fails on per-user
provisioned Store apps. All three are checked before anything starts, and a failed check
returns a refusal naming the reason rather than aborting part way through.

```powershell
# Recommended: boot the WinPE stick, then wipe the internal install
Invoke-DeviceReissueWipe -OfflineRoot C:\ -RemoveFromDomain -WipeMethod Secure

# Live, finishing with sysprep so it boots to OOBE and shuts down ready to hand over
Invoke-DeviceReissueWipe -RemoveFromDomain -Generalize

# Preview everything without changing anything
Invoke-DeviceReissueWipe -OfflineRoot C:\ -WhatIf
```

### Bootable WinPE Media

`New-EraseDriveBootMedia` builds the USB stick that makes an offline wipe possible.
Requires the Windows ADK and the WinPE add-on.

```powershell
New-EraseDriveBootMedia -UsbDriveLetter E      # erases E:
New-EraseDriveBootMedia -IsoPath D:\PE.iso     # for a VM or out-of-band management
```

The target must be removable media. A fixed disk is refused outright rather than
confirmed, because `MakeWinPEMedia` erases the target completely.

**BitLocker.** A corporate device is usually encrypted, and an encrypted volume is
unreadable from WinPE until unlocked, so the wipe will correctly report that it found no
Windows installation. The image ships `manage-bde` and the boot script flags locked
volumes on startup:

```
manage-bde -unlock C: -RecoveryPassword <48-digit key>
```

**Evidence stays with you.** Logs and the Certificate of Destruction are written to the
directory EraseDrive was launched from, which on the boot stick is the stick itself, not
the machine being handed over. Override with `-EvidencePath`.

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

Verification samples are compared against the byte the erase actually wrote, which is carried through from the method that wrote it rather than assumed. A certificate asserts NIST SP 800-88 Clear only when that verification passed. Use `-SkipVerification` to bypass (not recommended, and it also disables `-Reformat`).

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

### v3.1.0 (Current)
- Signed PDF Certificate of Destruction (Pro+ license tier)
- License-key file model (RSA-2048 signed, offline validation)
- "Load License..." button in GUI, tier badge in header
- License tier banner in CLI startup output
- Inno Setup-based code-signable installer (`installer/EraseDrive.iss`)
- Pricing tiers: Free (text cert only), Pro $99 lifetime, Team $499/yr, MSP $1499/yr

### v3.0.0
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

## License

EraseDrive is open source under the **Apache License, Version 2.0**. The full
text is in [LICENSE](LICENSE); attribution and trademark terms are in
[NOTICE](NOTICE).

The word "license" does double duty in this project, so to be explicit about
which is which:

| | What it is | Terms |
|---|---|---|
| **The software** | Everything in this repository | Apache-2.0. Fork it, read it, run it, modify it, redistribute it. |
| **An issued `.lic` file** | A signed credential tied to one purchase, unlocking the PDF Certificate of Destruction | Not open source and not redistributable. Yours to use, not to share. |
| **The signing key** | The RSA private key behind every certificate | Not in this repository and never will be. |

You can read every line before you let this near a disk, which for a tool whose
entire job is irreversible destruction seems like the minimum.

**On the paid tier and forks.** Nothing stops you removing the license check;
it is a few lines of PowerShell and the Apache License permits it. Worth
knowing what you get, though: the value of a Certificate of Destruction in an
audit is not the PDF, it is that an identifiable party with a legal entity
behind it attests to the erasure. A certificate a tool issued to itself is a
document you wrote about yourself. If you need one that stands up to a third
party, that is what the $99 buys.

**Trademarks.** Apache-2.0 section 6 does not grant rights to the "EraseDrive"
or "DarkHorse InfoSec" names. Derivative works are welcome, under a different
name.

---

## Legal Notice

This tool is provided as-is for legitimate data destruction purposes. Users are responsible for:

- Ensuring legal right to destroy the target data
- Compliance with organizational policies and regulations
- Proper backup of important information before use
- Understanding that these operations are **permanent and irreversible**
- Selecting appropriate sanitization methods for their compliance requirements

**DarkHorse InfoSec assumes no liability for data loss resulting from the use of this tool.**

---

**DarkHorse InfoSec** - EraseDrive v3.1.0

# EraseDrive installer

> **PARKED as of 2026-09-09. This installer is not shipped in v3.1.0.**
>
> No Authenticode certificate was purchased: roughly $300/yr against a project
> with zero revenue is not justified, and an unsigned `.exe` that destroys disks
> has the exact profile of malware. Asking sysadmins to click through "Windows
> protected your PC" to run a wiper trains the wrong instinct in precisely the
> audience whose trust the product needs. Signed installer or no installer.
>
> **v3.1.0 ships module-only: a ZIP plus a GitHub release.** A ZIP of `.ps1`
> files carries Mark-of-the-Web instead of a SmartScreen block, which
> `Unblock-File` clears and the top-level README documents.
>
> Everything below still works and is kept intact. It comes back in v3.2 if
> SignPath.io accepts the project for free open-source signing, or if revenue
> later justifies a paid certificate. Nothing here has ever been executed: the
> installer has never been built.

Inno Setup script + PowerShell build wrapper for producing the distributable, code-signable `EraseDrive-Setup-3.1.0.exe`.

## Prerequisites

- Windows 10 / 11 (64-bit) build machine.
- [Inno Setup 6](https://jrsoftware.org/isdl.php) installed in the default location (`C:\Program Files (x86)\Inno Setup 6`).
- Windows 10/11 SDK installed (for `signtool.exe`) when code-signing.
- For signing: any Authenticode `.pfx`, passed via `-PfxPath` or the `ERASEDRIVE_SIGNING_PFX` env var. No certificate has been obtained; see the note at the top.

## Build (unsigned, for local smoke testing)

```powershell
.\build-installer.ps1 -SkipSign
```

Output: `<repo-root>\dist\EraseDrive-Setup-3.1.0.exe`.

Do NOT distribute unsigned builds publicly. SmartScreen will block them for the IT-admin audience this product targets.

## Build (signed, for distribution)

Once you have a Sectigo OV `.pfx`:

```powershell
$env:ERASEDRIVE_SIGNING_PFX = 'C:\Users\<you>\Secrets\EraseDrive\sectigo-ov.pfx'
$env:ERASEDRIVE_SIGNING_PFX_PASSWORD = '<pfx password>'

.\build-installer.ps1
```

The wrapper runs `signtool` with:
- SHA-256 file digest (`/fd SHA256`)
- SHA-256 timestamp digest (`/td SHA256`)
- RFC-3161 timestamp via `http://timestamp.sectigo.com`
- Description "EraseDrive Forensic Disk Wiper"
- URL `https://erasedrive.io`

Then verifies with `signtool verify /pa /v`.

## What the installer ships

| Path inside installer | Source in repo |
|---|---|
| `<install>\EraseDrive\` (whole module tree) | `EraseDrive\` |
| `<install>\Start-EraseDrive.ps1` | `Start-EraseDrive.ps1` |
| `<install>\EraseDrive.bat` (self-elevating launcher) | `installer\EraseDrive.bat` |
| `<install>\logo.ico` | `logo.ico` |
| `<install>\logo.png` | `logo.png` |
| `<install>\README.md` | `README.md` |

Default install location: `%ProgramFiles%\DarkHorse\EraseDrive\`. Start Menu shortcut: `DarkHorse\EraseDrive\EraseDrive`.

The license file `license.lic` is NOT bundled with the installer. Customers place their `.lic` in `%ProgramData%\DarkHorse\EraseDrive\` themselves (or via the "Load License..." button in the GUI). This keeps the installer single-binary and the license customer-specific.

## Test plan

Before cutting a release:

1. `.\build-installer.ps1 -SkipSign` produces a .exe.
2. Run the .exe on a clean Win11 VM. Confirm: install completes, Start Menu shortcut appears, double-clicking the shortcut elevates and launches the GUI.
3. Wipe a USB stick from the GUI. Confirm: free-tier completion shows a .txt cert and the "Upgrade to Pro" hint.
4. Drop a Pro `.lic` into `%ProgramData%\DarkHorse\EraseDrive\license.lic`. Relaunch. Confirm: header shows "TIER: PRO".
5. Wipe a USB stick again. Confirm: both .txt and .pdf certs appear and the .pdf opens cleanly in Adobe Reader and Chrome.
6. Uninstall via Control Panel. Confirm: install dir is removed, Start Menu shortcut is removed, `%ProgramData%\DarkHorse\EraseDrive\` (logs, certs, license) is preserved (intentional - audit trail must survive uninstall).

For the signed release:

7. `.\build-installer.ps1` (with PFX env vars) produces a signed .exe.
8. Right-click the .exe -> Properties -> Digital Signatures -> confirm the Sectigo signature is valid.
9. On a fresh Edge profile, download the .exe and confirm SmartScreen does not block (may take a few hundred downloads for the OV cert to build reputation).

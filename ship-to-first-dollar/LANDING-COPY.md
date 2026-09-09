# EraseDrive landing page copy

Target page: `erasedrive.io` (or `darkhorseinfosec.com/erasedrive` if the dedicated domain is not yet registered at launch). Single page, no sign-up wall, two buttons above the fold: "Download (Free)" and "Buy Pro ($99)".

## Hero

> ## A $99 NIST 800-88 disk wiper that gives auditors what they actually want.
> 
> Free for the wipe. $99 lifetime for the signed PDF Certificate of Destruction.
> 
> Code-signed. SSD-aware. Multi-pass or single-pass. Built by a sysadmin who got tired of Blancco's pricing.
>
> **[Download (Free)]**   **[Buy Pro - $99]**

Below the hero: a 60-second YouTube embed (see DEMO-SCRIPT.md).

## The problem (3 lines)

You wiped the drive. Now your auditor wants proof. They want a PDF that names the drive, the method, the operator, and ideally a hash that says nobody tampered with the record. Blancco charges $25 per wipe for this. KillDisk charges $50 per seat per year. Both work fine; both are priced for enterprises with procurement departments.

## The solution (3 lines)

EraseDrive does the same NIST 800-88 wipe and the same compliance PDF, at $99 once. The wipe itself is free; you only pay if you need the certificate. Most refurb shops, e-waste vendors, and small MSPs need the certificate.

## What you get on the free tier

- NIST 800-88 Clear (single-pass) or Secure (3-pass: zeros, ones, random)
- SSD-aware: NVMe, SATA, USB
- Post-erase verification with random-sector sampling
- HMAC-signed text Certificate of Destruction (machine-bound)
- Windows Event Log audit trail
- GUI and CLI modes (CLI scripts into MDT/SCCM)
- Multi-step safety: typed confirmation, system-disk detection, RAID detection, hot-plug detection

## What $99 Pro adds

- **Signed PDF Certificate of Destruction**. The PDF auditors actually accept. Drive serial, wipe method, NIST 800-88 reference, signed timestamp, HMAC integrity signature, licensed-to line.
- All future versions, forever.
- Use on as many of your own workstations as you want.

## Plans

| Plan | Price       | Best for |
|------|-------------|----------|
| Free | $0          | Trying it out. Verifying it works on your drives. |
| Pro  | $99 once    | Single tech, single seat, lifetime updates. |
| Team | $499 / yr   | 5 techs (honor system; we believe you). |
| MSP  | $1499 / yr  | Unlimited techs, multi-tenant. |

All paid tiers unlock the signed PDF. Buy via Gumroad; license file emailed within 24 hours of purchase.

## How it stacks up

| | Blancco | KillDisk | EraseDrive |
|---|---|---|---|
| Per-wipe / per-seat pricing | Yes ($25/wipe) | Yes ($50/seat/yr) | No |
| NIST 800-88 compliant | Yes | Yes | Yes |
| Signed PDF certificate | Yes | Yes | Yes (Pro) |
| Code-signed installer | Yes | Yes | Yes |
| Open source wipe logic | No | No | Yes (PowerShell, readable) |
| Lifetime price | $$$$$ | $$$ | $99 once |

## FAQ

**Is the wipe actually free, or is there a watermark / nag?**
The wipe is free, no watermark, no nag dialog interrupting the wipe. Free tier still produces a text certificate; the Pro upgrade just adds the PDF rendering.

**What is NIST 800-88?**
The US government publication on media sanitization. "Clear" overwrites accessible storage; "Purge" goes further (firmware-level Secure Erase). EraseDrive's Secure method meets Clear for HDDs. For SSD Purge, you need the manufacturer's secure-erase tool; EraseDrive surfaces whether the drive supports it.

**Does the certificate actually satisfy my auditor?**
Auditors want a document that names the drive (model + serial), the method, the operator, the timestamp, and a way to confirm it wasn't tampered with. The EraseDrive Pro PDF includes all of those plus an HMAC-SHA256 signature tied to the machine that ran the wipe. We have not had an auditor reject one yet. If yours does, email us and we will work with you.

**Do I have to talk to a sales person?**
No. You will not hear from us unless you email us first.

**Does it phone home?**
No. The license file is signed offline. The app never connects to any server. You can run it on an air-gapped network.

**Refunds?**
Yes, within 30 days, no questions asked. Reply to your purchase email.

**Can I run it on bare metal / WinPE?**
The current build assumes a running Windows 10/11/Server 2016+ host. WinPE support is on the roadmap, not in v3.1.

**Why not just use `cipher /w` or `sdelete`?**
You can. EraseDrive's value is not the wipe (that is a few PowerShell lines); it is the audit artifact, the safety checks against wiping the wrong drive, and the signed certificate.

**Source code?**
The wipe module is on GitHub: github.com/HackingPain/EraseDrive. The license-signing infrastructure is closed (otherwise the licenses would not be worth anything).

## Footer

- erasedrive.io  -  contact@darkhorseinfosec.com  -  Made in Vermont
- Released under the [LICENSE] for the source code; the Pro PDF generator and license-signing components are proprietary and ship as part of the installer.

## Above-the-fold buttons

- **Download (Free)** -> link to the GitHub Releases v3.1.0 signed installer .exe (NOT to source code; users want the .exe).
- **Buy Pro ($99)** -> link to the Gumroad product page.
- Below those, a small "What's in the box" toggle that expands to show the table from "What you get on the free tier" + "What $99 Pro adds".

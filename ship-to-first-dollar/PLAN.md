# Ship to First Dollar: EraseDrive

## Claude Code Session Prompt

```
You are picking up work on EraseDrive, a NIST 800-88 compliant forensic disk wiper for Windows, targeting IT admins, MSPs, refurb shops, e-waste vendors, and compliance officers.

Read ship-to-first-dollar/PLAN.md in this directory IN FULL before starting any work. The current build is PowerShell 5.1+ with a .NET Framework 4.5+ Windows Forms GUI. The wiping logic works. The goal of this work is to add the paid feature (Certificate of Destruction PDF), get the installer code-signed, and ship a Gumroad or Lemon Squeezy listing within 10 days.

Start by entering plan mode. The pricing model is freemium: free tier wipes drives all day, paid tier ($99 one-time or $499/yr team) unlocks the signed Certificate of Destruction PDF with drive serial, wipe method, NIST 800-88 reference, and signed timestamp. This is the compliance artifact auditors want and is the entire reason buyers pay.

Constraints:
- Do not build a license server. Use a license-key file model that unlocks the cert generator locally.
- Do not add features beyond PLAN.md. The goal is revenue, not scope.
- Code-signing requires an Authenticode certificate ($200 to $400 from Sectigo or similar). The installer must be signed before public distribution; 2026 Windows SmartScreen will block unsigned installers for IT-admin audiences.
- Do not build a payment system. Use Gumroad or Lemon Squeezy to handle checkout and license-key delivery.
- No em dashes in code, prose, or commit messages per global CLAUDE.md.
- Mark task checkboxes complete in PLAN.md as you finish them.
```

---

## Pitch positioning

Free for the wipe, $99 lifetime for the Certificate of Destruction PDF that auditors require. Underdog alternative to Blancco ($25 per wipe) and KillDisk.

## Current state

- Stack: PowerShell 5.1+, .NET Framework 4.5+, Windows Forms GUI
- Working: drive wipe logic with safety checks
- Documentation: clear UX and safety docs
- Missing: signed installer, payment flow, Certificate of Destruction feature, landing page

## Gap to first dollar (4 to 6 dev days)

- [ ] Obtain an Authenticode code-signing certificate ($200 to $400 from Sectigo). Sign the MSI or EXE installer. Unsigned installers will not run on a typical 2026 IT-admin Windows box without SmartScreen warnings.
  - Installer build + signtool integration is DONE (`installer/EraseDrive.iss`, `installer/build-installer.ps1`). Awaiting Sectigo OV cert procurement, then run `build-installer.ps1` with `ERASEDRIVE_SIGNING_PFX` set.
- [x] Certificate of Destruction PDF feature. Captures drive serial number, wipe method (DoD 5220.22-M, NIST 800-88 Clear, NIST 800-88 Purge), pass count, start and end timestamps, operator name, all signed with a cert. Free tier omits this; paid tier generates it.
  - `EraseDrive/Private/New-PdfCertificate.ps1` (hand-crafted, no external deps). Gated by license tier in `New-ErasureCertificate.ps1`. Pester tests in `Tests/PdfCertificate.Tests.ps1`.
- [x] License-key file model. Generate a signed key file on purchase; the app validates locally on launch. No license server, no callouts to a backend.
  - RSA-2048 signed `.lic` files. `EraseDrive/Private/Test-EraseDriveLicense.ps1` validates locally. `licensing/` contains the dev-only keypair generator, issuer, and verifier. Pester tests in `Tests/License.Tests.ps1`.
- [ ] Gumroad or Lemon Squeezy listing. Skip building a payment system; use a marketplace that handles checkout, license-key delivery, refunds, and EU VAT.
  - Listing copy + fulfillment workflow drafted in `ship-to-first-dollar/GUMROAD-LISTING.md`. Awaiting Domenic to create the Gumroad product.
- [ ] Landing page at erasedrive.io or a subdomain off darkhorseinfosec.com.
  - Copy + FAQ drafted in `ship-to-first-dollar/LANDING-COPY.md`. Awaiting Domenic to register / point a domain and publish the page.
- [ ] 60-second demo video. Screencast: pick drive, click wipe, cert PDF appears in folder. Upload to YouTube and embed on landing page.
  - Shot list + voiceover script drafted in `ship-to-first-dollar/DEMO-SCRIPT.md`. Awaiting Domenic to record and upload.

## Pricing

| Plan | Price | Use |
|------|-------|-----|
| Free | $0 | Unlimited wipes, no cert |
| Pro | $99 one-time | Lifetime, single tech, cert generation |
| Team | $499/yr | 5 techs plus central audit log |
| MSP | $1,499/yr | Unlimited techs plus multi-tenant plus branded certs |

## First 10 customers (community-led GTM)

1. r/sysadmin post: "Built a NIST 800-88 wiper after Blancco's pricing pushed me over the edge. Free for the wipe, $99 lifetime for the cert PDF." Expect 3 to 5 sales from a well-received post.
2. r/sysadmin sale #2.
3. r/sysadmin sale #3.
4. Spiceworks community post.
5. r/msp post.
6. Cold email to Vermont MSP #1 (5 to 20 employees). Subject: "Replace your Blancco license."
7. Cold email to Vermont MSP #2. Target volume: 50 New England MSP emails.
8. Refurb shop in New England, direct phone call.
9. E-waste vendor in New England, direct phone call.
10. Regional MSP meetup tabling. Free booth, hand out USB stick with installer.

## Cold pitch (email or forum post)

> If you are paying Blancco or KillDisk per-wipe, this is a $499/yr unlimited replacement with NIST 800-88 Certificates of Destruction. Free tier wipes drives all day; the $99 lifetime unlocks the cert PDFs your auditor wants. Try it on a junk drive first, installer link below. Code-signed, no SmartScreen warnings.

## Why this sells

IT admins love a Blancco underdog. The Certificate of Destruction PDF is a tangible compliance artifact, not a vague feature. One-time pricing reduces purchase objection. Reddit and Spiceworks distribution is free; no paid acquisition needed for the first 10 customers.

## Success metric

First $99 sale within 10 days of the cert feature shipping. Five Pro sales within 30 days. One Team or MSP subscription within 60 days.

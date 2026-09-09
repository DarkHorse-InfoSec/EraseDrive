# EraseDrive Gumroad listing

Set this up at gumroad.com using a personal Gumroad account. No need for the "Discover" toggle; we are driving traffic from r/sysadmin and the landing page directly.

## Product (use Gumroad's "Versioned" or "Tiered" product format)

**Cover image:** EraseDrive logo over a dark gradient, with the text "NIST 800-88 disk wiper. $99 lifetime."

**Product name:** EraseDrive Pro - NIST 800-88 Certificate of Destruction

**Tagline (Gumroad subtitle):** $99 lifetime. Signed PDF certs your auditor will accept. SSD-aware. Code-signed installer. Built by a sysadmin who got tired of Blancco's pricing.

**Description (use Gumroad's rich-text editor):**

> EraseDrive is a NIST 800-88 compliant disk wiper for Windows with a paid Certificate of Destruction PDF. The wipe itself is free at erasedrive.io. This Gumroad listing unlocks the signed PDF certificate that auditors actually accept.
>
> ## What you get when you buy
>
> - A signed `.lic` license file emailed within 24 hours of purchase.
> - Every wipe you run after activating the license generates a PDF Certificate of Destruction next to the text certificate.
> - The PDF includes: drive serial, wipe method, NIST SP 800-88 Rev. 1 reference, UTC timestamp, machine-bound HMAC-SHA256 integrity signature, your name and license ID.
> - Lifetime updates on the Pro tier. New EraseDrive releases continue to validate your existing license.
> - Use on as many of your own workstations as your tier allows (honor system; we believe you).
>
> ## What you do NOT get
>
> - A cloud account. There is no account. We do not phone home.
> - Per-wipe pricing. Wipe as many drives as you want; the license is unlimited.
> - A subscription billing surprise. Pro is one-time. Team and MSP are annual and clearly labeled.
>
> ## Tiers
>
> - **Pro - $99 once.** Single technician, lifetime updates, perpetual license.
> - **Team - $499 per year.** 5 techs (honor system), all Pro features.
> - **MSP - $1,499 per year.** Unlimited techs, multi-tenant, all Team features.
>
> ## How activation works
>
> 1. Buy here.
> 2. We email you a license file (`license.lic`) within 24 hours, usually within an hour.
> 3. Install EraseDrive from erasedrive.io if you have not already.
> 4. Drop the `license.lic` into `%ProgramData%\DarkHorse\EraseDrive\`, or click "Load License..." in the GUI.
> 5. Wipe any drive. The PDF appears alongside the text certificate.
>
> ## Refunds
>
> 30 days, no questions asked. Reply to the purchase email.
>
> ## Questions
>
> contact@darkhorseinfosec.com. Replies usually within 24 hours, often within 1.

## Variants / tiers (Gumroad "versions")

| Version name              | Price (USD) | Recurring? | Internal SKU |
|---------------------------|-------------|------------|---------------|
| EraseDrive Pro (lifetime) | 99          | No         | EDR-PRO       |
| EraseDrive Team (annual)  | 499         | Yearly     | EDR-TEAM      |
| EraseDrive MSP (annual)   | 1499        | Yearly     | EDR-MSP       |

## Fulfillment (manual for v1)

Gumroad does NOT generate the license file. We do, manually. Workflow:

1. Set up a Gmail filter for "Gumroad notification" -> tag "ED-PURCHASE".
2. When a purchase notification arrives, capture: buyer name, buyer email, Gumroad order ID, version purchased.
3. Open a PowerShell prompt with the private key path handy. Run:
   ```powershell
   cd D:\Projects\Open-Source\EraseDrive-gh\licensing
   .\New-EraseDriveLicense.ps1 `
       -CustomerName 'Buyer Name from Gumroad' `
       -CustomerEmail 'buyer@example.com' `
       -Tier Pro `
       -PurchaseId 'GUMROAD-XXXXX' `
       -PrivateKeyPath 'C:\Users\you\Secrets\EraseDrive\license-private.xml'
   ```
   For Team / MSP, add `-Tier Team` (or MSP) and `-ExpiresAt (Get-Date).AddYears(1)`.
4. The script outputs `EraseDrive-License-<Customer>-<LicenseId>.lic`. Optionally sanity-check it:
   ```powershell
   .\Test-IssuedLicense.ps1 -LicensePath .\EraseDrive-License-<Customer>-<LicenseId>.lic
   ```
5. Reply to the customer's purchase-confirmation email. Attach the `.lic`. Use the boilerplate in `licensing/README.md`.

Target turnaround: 24 hours. If you are about to be AFK for longer (vacation, conference), set up a Gumroad auto-responder that says "License files arrive within 24 hours; I am currently away until <date>."

## Tax / VAT

Gumroad handles US sales tax and EU VAT automatically. Do not configure anything custom; the defaults are correct for a small US-based seller.

## Receipts

Gumroad emails the receipt. The license email is separate (manual). Customers should keep both for auditing.

## Refunds workflow

If a buyer asks for a refund:

1. Open the Gumroad sale, click Refund.
2. Note the license ID in `licensing/revoked-licenses.txt` (create the file if it does not exist). v1 has no online revocation; the customer's license continues to function locally. That is acceptable at v1 sales volume.
3. Reply: "Refunded, please uninstall EraseDrive. If you reinstall later, the license will still work; we operate on the honor system at this price point."

## Roadmap items NOT to commit to in the listing copy

- WinPE / bootable USB version
- Team central audit dashboard
- MSP multi-tenant branded PDFs
- Online license revocation
- macOS, Linux

These are sometimes asked for; the answer is "on the roadmap, not yet." Do not pre-sell them.

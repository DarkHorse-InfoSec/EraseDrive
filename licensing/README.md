# EraseDrive Licensing - Operator Handbook

This directory contains the dev-only tooling for issuing EraseDrive Pro / Team / MSP licenses. End users never see these scripts. Only Domenic (or a trusted operator) runs them.

## One-time setup

1. Pick a path for the private key OUTSIDE this repository. Example:
   `C:\Users\<you>\Secrets\EraseDrive\license-private.xml`
2. Generate the keypair:
   ```powershell
   .\New-EraseDriveLicenseKeyPair.ps1 -PrivateKeyOutPath 'C:\Users\<you>\Secrets\EraseDrive\license-private.xml'
   ```
   This writes the public key to `EraseDrive\EraseDriveLicense.pub` (commit it) and the private key to the path you provided (NEVER commit it).
3. Back up the private key to your password manager (1Password, Bitwarden, etc.). If you lose it, you cannot issue new licenses without rotating keys (which invalidates every existing customer license).
4. Commit the public key:
   ```powershell
   git add EraseDrive/EraseDriveLicense.pub
   git commit -m 'add: EraseDrive license public key'
   ```

## Per-sale workflow

When you get a Gumroad sale notification:

1. Note the buyer's name, email, and Gumroad order ID.
2. Issue the license:
   ```powershell
   .\New-EraseDriveLicense.ps1 `
       -CustomerName 'Acme Refurb, LLC' `
       -CustomerEmail 'ops@acmerefurb.com' `
       -Tier Pro `
       -PurchaseId 'GUMROAD-ABC123' `
       -PrivateKeyPath 'C:\Users\<you>\Secrets\EraseDrive\license-private.xml'
   ```
   Use `-Tier Pro` for $99 lifetime, `-Tier Team` with `-ExpiresAt (Get-Date).AddYears(1)` for $499/yr, `-Tier MSP` with `-ExpiresAt (Get-Date).AddYears(1)` for $1499/yr.
3. (Optional) Sanity-check the issued license before sending:
   ```powershell
   .\Test-IssuedLicense.ps1 -LicensePath .\EraseDrive-License-Acme_Refurb__LLC-EDR-Pro-...lic
   ```
4. Reply to the customer's purchase-confirmation email with the `.lic` file attached. Suggested boilerplate:

   > Thanks for purchasing EraseDrive Pro. Your license file is attached as `license.lic`.
   >
   > **To activate:** save `license.lic` to `C:\ProgramData\DarkHorse\EraseDrive\` (you may need to create that folder on first install) and relaunch EraseDrive. The header should now show "PRO". Every certificate you generate from this machine forward will include the signed PDF.
   >
   > Or in the GUI: click "Load License..." and select the attached file.
   >
   > The license is keyed to your name and email (visible to your auditors on the certificate). It is not tied to a specific machine - install on as many workstations as your tier allows.
   >
   > Questions or refund requests within 30 days: reply to this email.

## Tier policy (v1 honor-based)

| Tier | Price       | Implied scope                          | Enforcement      |
|------|-------------|-----------------------------------------|------------------|
| Pro  | $99 one-time | 1 technician, 1 workstation          | Honor system     |
| Team | $499 / yr   | 5 technicians, central audit log target | Honor system + annual expiry |
| MSP  | $1499 / yr  | Unlimited technicians, multi-tenant     | Honor system + annual expiry |

v1 does NOT implement seat counting, central audit collection, or multi-tenant branding. Those are explicitly out of scope per `ship-to-first-dollar/PLAN.md`. The license file communicates the tier, but the app does not enforce per-seat limits. If a Team customer asks for branded PDFs, that is a v1.x roadmap item, not a launch blocker.

## What to do if a private key leaks

1. STOP issuing new licenses with the leaked key.
2. Generate a new keypair with `New-EraseDriveLicenseKeyPair.ps1 -Force` and a fresh `-PrivateKeyOutPath`.
3. Cut a new release of EraseDrive that bundles the new public key.
4. Re-issue licenses to every existing customer using the new key. Email them the new `.lic` and the new installer (if needed) with a brief explanation.
5. Document the incident in the EraseDrive incident log.

Honor a 30-day grace window where the old key is still trusted alongside the new one if you need to soft-rotate (this would require shipping both public keys in the module; not implemented in v1).

## What to do if a customer requests a refund

1. Process the Gumroad refund.
2. Add the customer's license ID to a revocation list. v1 does not have a revocation mechanism - the customer's license continues to work locally. This is acceptable for low-volume v1 sales. If revocation becomes important, see the v1.x roadmap note in `ship-to-first-dollar/PLAN.md`.

## Files in this directory

- `New-EraseDriveLicenseKeyPair.ps1` - one-time keypair generator
- `New-EraseDriveLicense.ps1` - per-customer issuer
- `Test-IssuedLicense.ps1` - sanity-check verifier
- `README.md` - this file

None of these are shipped to customers. They are dev-only.

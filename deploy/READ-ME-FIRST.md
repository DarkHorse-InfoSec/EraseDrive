# READ ME FIRST

Deployed 2026-09-10. Read this before running anything.

---

## The short answer to "can this make a laptop like new?"

**Not yet. Not tomorrow.**

The function that does exactly what you described - remove every user, unjoin the
domain, run sysprep so it boots to out-of-box setup like a new machine - is
called `Invoke-DeviceReissueWipe`. It exists, it is in this folder, and **it is
deliberately not callable.**

It ships dormant because **it has never been executed against a real machine,
not once.** A test asserts that it stays unexported until it has been. Turning it
on so it could be used tomorrow would mean running an unproven destructive
function against a real laptop, first time, live. That is the one thing this
project does not do.

Three specific things are unproven, not just untested-in-general:

1. **The domain unjoin has never run.** `Remove-DomainMembership` has only ever
   reached its "this device is not domain joined, nothing to do" early return.
2. **Removing EVERY user requires the offline path.** A live wipe cannot remove
   the profile of the person running it. Complete removal needs the WinPE boot
   media, and `New-EraseDriveBootMedia` **has never been executed either** and
   needs the Windows ADK, which is not installed.
3. **Sysprep /generalize has never run** from this tool.

**If the actual goal tomorrow is a laptop that behaves like new, use Windows'
own "Reset this PC" with the remove-everything option, or reinstall from
installation media.** That is proven, free, takes about an hour, and genuinely
produces an out-of-box machine. It will not give you a signed certificate of
destruction, which is the thing this tool exists to add, but it will give you the
outcome.

---

## What IS usable tomorrow

### 1. Readiness check - start here, always

Read-only. Changes nothing. Run it on the target device before anything else.

```powershell
E:\tools\Test-EraseDriveReadiness.ps1
```

Tells you whether the module will even load on that machine, and why not if not:
elevation, PowerShell language mode (WDAC/AppLocker), execution policy and which
policy scope set it, which antivirus is active and whether it blocks the module,
domain membership, and every disk marked eligible or refused.

**It will very likely find blockers on a managed device.** That is the point. It
is much better to learn that from a read-only script than halfway through a wipe.

### 2. Reissue wipe DRY RUN - the useful thing to do tomorrow

```powershell
E:\tools\Invoke-ReissueDryRun.ps1
```

Shows exactly what the reissue wipe WOULD do on that specific domain-joined
device: which profiles it would target, which it would skip and why, whether it
sees the domain, where the certificate would go.

**It destroys nothing and cannot be made to.** `-WhatIf` is hard-coded,
`$WhatIfPreference` is forced for the whole scope, and the script accepts no
argument that could turn either off. It refuses to run on a machine that is not
domain joined, because there would be nothing to learn.

This is the single most valuable thing you can do tomorrow. It turns "we think it
would work" into a real observation from a real domain device, and it is the
evidence needed before the function is ever made live.

The transcript is written to `EraseDrive-Evidence\` on this stick, so bring it
back.

### 3. Erase a SECONDARY or EXTERNAL disk - proven

```powershell
Import-Module E:\EraseDrive -Force
Start-EraseDriveGUI
```

This path is proven on real hardware: 123,041,963,520 bytes written in 01:28:40,
verification 2404 of 2404 samples clean, certificate issued. It refuses the
system and boot disk by design, and it refuses the stick it is running from.

### 4. User data wipe - EXPORTED, WORKS, NEVER RUN FOR REAL

`Invoke-ForensicUserDataWipe` will run if you call it. **It has never been run
destructively; all 84 of its tests mock the parts that destroy.** On a domain
machine it cannot remove the operator's own profile, so the result is incomplete
by construction and says so.

If you touch it at all tomorrow, use `-WhatIf` and stop there:

```powershell
Invoke-ForensicUserDataWipe -WhatIf
```

---

## Requirements on the target machine

- **Elevated Windows PowerShell 5.1.** Not PowerShell 7, and not a normal prompt.
  Right-click, Run as administrator.
- **Local administrator rights**, which a managed domain account often does not
  have.
- If the module will not import, run the readiness check and read what it says
  rather than guessing.

## Known problem you may hit immediately

Some antivirus products flag `EraseDrive\Private\Test-EraseVerification.ps1` and
refuse to let the module load, with "This script contains malicious content".
That is a **false positive** on a read-only verification function, reported to
the vendor on 2026-09-10.

On a managed device you will probably not be able to add an exclusion, and it may
alert the security team. **Check with whoever owns that device before running
anything on it.** The readiness check detects this condition and names it.

## The evidence folder

`EraseDrive-Evidence\` on this stick is where logs, transcripts and certificates
are written, so the audit trail leaves with the stick rather than staying on the
machine that was wiped. Bring the stick back.

## Do not

- Do not run any destructive operation on a device you cannot afford to lose,
  tomorrow or otherwise, until the dry run has been read and understood.
- Do not run `Invoke-ForensicUserDataWipe` for real on a machine with service
  accounts that have profiles. On the MSI, `C:\Users\postgres` is a real profile
  and a valid target whenever PostgreSQL is stopped.
- Do not add an antivirus exclusion on someone else's managed device without
  their administrator agreeing to it.

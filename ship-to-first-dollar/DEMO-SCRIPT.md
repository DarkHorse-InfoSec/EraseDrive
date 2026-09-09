# EraseDrive: 60-second demo screencast

## Recording setup

- Windows 11 VM, 1080p, dark mode, fresh user profile.
- Plug in a USB stick with junk data (must be safe to wipe, not a system drive).
- OBS recording at 1920x1080, 30 fps. Mouse cursor effects on (highlight clicks).
- Voiceover recorded separately with a half-decent mic. Read the script aloud, no rambling, edit out breaths.
- Total target: 55 to 60 seconds. Anything over 75 is too long for r/sysadmin.

## Shot list (timestamped, 60s budget)

### 0:00 to 0:05 - Hook (5s)
**On screen:** Black slide. Bold white text: "If your auditor needs proof you wiped a drive, this is the cheapest way."
**Voiceover:** "If your auditor needs proof you wiped a drive, this is the cheapest way to give it to them."

### 0:05 to 0:10 - Pricing snap (5s)
**On screen:** Slide: "Free for the wipe. $99 lifetime for the signed certificate."
**Voiceover:** "EraseDrive is free for the wipe. Ninety-nine dollars lifetime for the signed certificate."

### 0:10 to 0:18 - Launch (8s)
**On screen:** Double-click Start Menu shortcut. GUI opens with the dark theme. Header reads "TIER: PRO" in green.
**Voiceover:** "Launch it. NIST 800-88 compliant, SSD-aware, multi-pass overwrite or single-pass clear."

### 0:18 to 0:32 - Wipe (14s, sped up)
**On screen:** Click the USB stick row (green, safe to erase). Check "Data backed up". Pick "Standard" from the Method dropdown. Click "ERASE DISK". Type "ERASE". Click OK. Progress bar runs. CUT to completion dialog.
**Voiceover (over the time-lapsed wipe):** "Pick the drive. Confirm. Wipe. Done."

### 0:32 to 0:48 - Certificate reveal (16s)
**On screen:** Completion dialog shows "Certificate (TXT)" and "Certificate (PDF)" paths. Close dialog. Open File Explorer to %ProgramData%\DarkHorse\EraseDrive\Certificates\. Double-click the .pdf. PDF opens, scroll slowly: Certificate ID, Operator, Disk Serial, Method, NIST reference, HMAC signature.
**Voiceover:** "A signed PDF Certificate of Destruction. Drive serial, wipe method, NIST 800-88 reference, machine-bound HMAC. Hand it to your auditor."

### 0:48 to 0:55 - Comparison (7s)
**On screen:** Slide: "Blancco: $25 per wipe.  KillDisk: $50 per seat per year.  EraseDrive: $99 lifetime."
**Voiceover:** "Blancco is twenty-five dollars per wipe. KillDisk is fifty dollars per seat per year. EraseDrive is ninety-nine, once."

### 0:55 to 0:60 - CTA (5s)
**On screen:** Slide: "erasedrive.io" with the logo and a "Try the free tier" button.
**Voiceover:** "Free tier installer at erasedrive.io. Try it on a junk drive first."

## Notes for recording

- DO NOT show real drive serials or operator names on screen. Wipe with a test user "DEMO\operator" and a USB stick whose serial you do not mind being public.
- Run the wipe on a small USB (8 GB or less) so the time-lapse from 0:18 to 0:32 is reasonable.
- The PDF reveal at 0:32 is the entire reason this is paid. Linger on the HMAC line. Zoom in if needed.
- DO NOT include any audio licensed music. Use a free-license track from YouTube Audio Library or no music at all.

## Upload checklist

- Title: "EraseDrive - $99 NIST 800-88 disk wiper with signed cert PDF"
- Description: copy the cold pitch from `ship-to-first-dollar/PLAN.md` and the erasedrive.io link.
- Tags: erasedrive, NIST 800-88, disk wipe, Blancco alternative, KillDisk alternative, certificate of destruction, IT admin tools, MSP tools.
- Pin a comment with the Gumroad and GitHub release links.
- Add to the landing-page hero. Embed via YouTube iframe.

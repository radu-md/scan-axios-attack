# Scan-AxiosAttack

> **PowerShell scanner for the axios npm supply chain attack (2026-03) — Windows**

On March 2026, two axios versions were quietly backdoored on npm by the [**UNC1069** threat actor](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package). Anyone who ran `npm install` with `axios@1.14.1` or `axios@0.30.4` in range may have a remote-access trojan installed on their machine.

This script scans your system for all known indicators of compromise. **It makes no changes to your system.**

---

## Quick Start

Open **PowerShell** or **Windows Terminal** and run:

```powershell
pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1
```

That's it. The script automatically looks in the most common places where developers keep projects on Windows.

---

## Threat Details

| | |
|---|---|
| **Compromised packages** | `axios@1.14.1` and `axios@0.30.4` |
| **Phantom dependency** | `plain-crypto-js@4.2.1` (silently installed alongside axios) |
| **RAT dropped to** | `C:\ProgramData\wt.exe` (disguised as Windows Terminal) |
| **Persistence** | `C:\ProgramData\system.bat` + registry Run key `MicrosoftUpdate` |
| **C2 server** | `sfrclak.com` / `142.11.206.73:8000` |
| **Secondary C2** | `23.254.167.216` (suspected UNC1069 infrastructure) |
| **Malware family** | WAVESHAPER.V2 (Windows PowerShell, macOS binary, Linux Python) |
| **Dropper** | SILKBELL (`setup.js`) |
| **Attributed to** | UNC1069 (active since 2018) |

---

## Requirements

- **Windows 10 / 11** (PowerShell 5.1 or PowerShell 7+)
- Run as your **normal user** — no admin required for most checks
- `git` in your PATH only if you use `-Deep` (optional)

---

## How to Run

### Option 1 — Auto scan (recommended for most users)

The script will automatically find and scan common project folders on your machine
(`%USERPROFILE%\source`, `%USERPROFILE%\repos`, `C:\dev`, `D:\dev`, etc.).

```powershell
pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1
```

### Option 2 — Scan a specific folder

Tell the script exactly where your projects live:

```powershell
pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1 -ScanPaths "D:\Workspace"
```

### Option 3 — Scan multiple folders

```powershell
pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1 -ScanPaths "C:\Projects","D:\Work","E:\Repos"
```

### Option 4 — Full deep scan (includes git history)

Use `-Deep` to also search git commit history. Slower, but catches cases where the
malicious package was already deleted from disk.

```powershell
pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1 -ScanPaths "D:\Workspace" -Deep
```

---

## Where are my projects? (Common Windows paths)

Not sure what to put in `-ScanPaths`? Here are the most common locations:

| Tool / Habit | Typical path |
|---|---|
| Visual Studio default | `C:\Users\YourName\source\repos` |
| VS Code / general | `C:\Users\YourName\projects` or `C:\dev` |
| Second drive | `D:\dev`, `D:\Projects`, `D:\Work` |
| IIS web apps | `C:\inetpub\wwwroot` |
| OneDrive synced | `C:\Users\YourName\OneDrive\Projects` |

You can also just point it at your entire user profile to catch everything (slower):

```powershell
pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1 -ScanPaths "C:\Users\YourName"
```

---

## What It Checks

| # | What | Why |
|---|---|---|
| 1 | `node_modules\axios\package.json` version | Directly identifies a compromised install |
| 2 | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb` | Lockfiles record every package that was ever resolved, even if deleted |
| 3 | `node_modules\plain-crypto-js` folder | The phantom dependency directory (malware may self-delete it) |
| 4 | `C:\ProgramData\wt.exe`, `system.bat`, `%TEMP%\6202033.ps1` | Known RAT drop paths and dropper temp payload |
| 5 | Active TCP connections + DNS cache | Detects live or recent C2 communication to `142.11.206.73`, `23.254.167.216`, port `8000` |
| 6 | Git commit history *(requires `-Deep`)* | Catches deleted traces across all commits |
| 7 | Global npm/yarn install | Affects every project on the machine if compromised globally |
| 8 | npm cache + tarball SHA1 hashes | Confirms presence via cryptographic file hashes |
| 9 | Registry Run key `MicrosoftUpdate` | Persistence mechanism that survives reboots |
| 10 | SHA256 hash verification of artifacts on disk + cache | Confirms known-malicious files using authoritative GTIG hashes |

---

## Understanding the Output

```
  [CRITICAL]  AXIOS_VERSION — Found compromised axios@1.14.1
              Path: D:\Workspace\my-app\node_modules\axios\package.json

  [WARNING]   C2_DNS — C2 domain 'sfrclak.com' found in DNS cache

  [OK] axios@1.8.4 — D:\Workspace\other-app\node_modules\axios\package.json
```

- 🔴 **CRITICAL** — strong indicator of compromise, act immediately
- 🟡 **WARNING** — suspicious, needs manual review
- 🟢 **OK / CLEAN** — no issues found

If any findings exist, a timestamped CSV is saved to the current folder:
```
axios-scan-results-20260403-143022.csv
```

---

## If You Get a CRITICAL Finding

> **Do not just delete files and move on.**

1. **Stop using the machine for sensitive work** until it is cleaned
2. **Rotate all credentials** stored on or used from this machine:
   - npm tokens (`~/.npmrc`)
   - SSH private keys (`~/.ssh/`)
   - API keys, cloud credentials (AWS, Azure, GCP)
   - Database passwords
3. **Check your CI/CD pipelines** — if a pipeline ran `npm install` with these versions, rotate secrets there too
4. **Block at your firewall/DNS**: `sfrclak.com`, `142.11.206.73`, and `23.254.167.216`
5. **Remove persistence**: delete `C:\ProgramData\system.bat` and remove the `MicrosoftUpdate` value from `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
5. **Wipe and rebuild** from a clean OS image if possible
6. **Audit git history** for any unauthorized commits

---

## Indicators of Compromise (IOC Reference)

### Network

| Indicator | Type | Notes |
|---|---|---|
| `142.11.206.73` | C2 IP | WAVESHAPER.V2 |
| `sfrclak.com` | C2 Domain | WAVESHAPER.V2 |
| `http://sfrclak.com:8000` | C2 URL | WAVESHAPER.V2 beacon (60s interval) |
| `23.254.167.216` | IP | Suspected UNC1069 infrastructure |

### Files

| Indicator | Notes |
|---|---|
| `C:\ProgramData\wt.exe` | PowerShell copy disguised as Windows Terminal |
| `C:\ProgramData\system.bat` | Hidden persistence batch file |
| `%TEMP%\6202033.ps1` | Stage-1 Windows dropper payload |

### Registry

| Key | Value | Notes |
|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `MicrosoftUpdate` | Launches `system.bat` at logon |

### SHA256 Hashes

| Hash | Description |
|---|---|
| `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` | WAVESHAPER.V2 — Linux Python RAT |
| `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` | WAVESHAPER.V2 — macOS native binary |
| `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` | WAVESHAPER.V2 — Windows Stage 1 |
| `ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c` | WAVESHAPER.V2 |
| `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` | SILKBELL (`setup.js`) — JS dropper |
| `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd` | `system.bat` |
| `58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668` | `plain-crypto-js-4.2.1.tgz` |

*Source: [Google Threat Intelligence Group](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package)*

---

## Prevention — Stop This From Happening Again

This attack succeeded because there was nothing between `npm install` and your disk.
[`@aikidosec/safe-chain`](https://www.npmjs.com/package/@aikidosec/safe-chain) fixes that.

### What it does

Safe Chain wraps your package managers (`npm`, `yarn`, `pnpm`, `bun`, `npx`, `pip`, etc.)
and **scans every package in real time before it is installed**. If a package is malicious,
the install is blocked and you are alerted — before anything touches your machine.

- 🛡 **Real-time malware scanning** — checks against Aikido's open-source threat intelligence database  
- ⏱ **24-hour quarantine window** — automatically blocks packages published in the last 24 hours (covers the critical window when supply chain attacks are most dangerous)  
- 🔍 **Catches** backdoored releases, dependency confusion, typosquatting, obfuscated code, data exfiltration scripts  
- ⚙️ **Zero workflow change** — keep using `npm install` as normal; Safe Chain works silently in the background  
- 🔒 **No license key, no telemetry, free to use**  
- 🤖 **CI/CD ready** — works in GitHub Actions, Azure Pipelines, and others  

### Install (one time, global)

```powershell
npm install -g @aikidosec/safe-chain
```

Then **restart your terminal**. That's it — all future `npm install` runs are protected.

> The axios attack described in this repo would have been **blocked by Safe Chain**
> because `plain-crypto-js@4.2.1` matched known malware signatures and was published
> within the quarantine window.

---

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-ScanPaths` | No | One or more folders to scan. Defaults to common Windows dev locations. |
| `-Deep` | No | Also search git commit history (slower). |

---

## License

Provided as-is for incident response and security auditing purposes.

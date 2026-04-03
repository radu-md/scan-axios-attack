<#
.SYNOPSIS
    Scans your Windows machine for the axios npm supply chain attack (2026-03-31).

.DESCRIPTION
    On March 2026, two axios versions were compromised on npm by the UNC1069
    threat actor. Installing axios@1.14.1 or axios@0.30.4
    also silently installed a phantom package (plain-crypto-js@4.2.1) that dropped
    the WAVESHAPER.V2 remote-access trojan onto the host.

    This script checks your machine for all known indicators of compromise (IOCs):
      1. Compromised axios versions in node_modules
      2. Phantom dependency in lockfiles
      3. Phantom dependency in node_modules (may self-delete after infection)
      4. RAT artifact on disk  (%ProgramData%\wt.exe)
      5. Active C2 connections / DNS cache entries
      6. Git history containing plain-crypto-js  (requires -Deep)
      7. Compromised axios in global npm/yarn install
      8. Compromised packages in local npm cache

    NO changes are made to your system. This script is read-only.

.PARAMETER ScanPaths
    One or more folders to scan for Node.js projects.
    If omitted the script automatically scans the most common Windows
    development locations under your user profile.

    Examples:
      -ScanPaths "C:\Users\You"
      -ScanPaths "C:\Work", "C:\Repos"

.PARAMETER Deep
    Also search git commit history in every repository found under ScanPaths.
    This is slower but will catch cases where plain-crypto-js was present and
    then deleted from the working tree.

.EXAMPLE
    # Quick scan — auto-detects common project folders
    pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1

.EXAMPLE
    # Scan a specific folder and include git history
    pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1 -ScanPaths "C:\Workspace" -Deep

.EXAMPLE
    # Scan multiple folders
    pwsh -ExecutionPolicy Bypass -File .\Scan-AxiosAttack.ps1 -ScanPaths "C:\Projects","C:\Workspace" -Deep
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "One or more folders to scan (e.g. 'C:\Projects','C:\Workspace'). Defaults to common Windows dev locations.")]
    [string[]]$ScanPaths,

    [Parameter(HelpMessage = "Also search git commit history for plain-crypto-js. Slower but more thorough.")]
    [switch]$Deep
)

# ── Configuration ──────────────────────────────────────────────────────────────
$BadVersions       = @("1.14.1", "0.30.4")
$PhantomDep        = "plain-crypto-js"
$C2IP              = "142.11.206.73"
$C2Domain          = "sfrclak.com"
$RatPath           = "$env:PROGRAMDATA\wt.exe"
$XorKey            = "OrDeR_7077"

$BadSHA1 = @{
    "axios@1.14.1"           = "2553649f2322049666871cea80a5d0d6adc700ca"
    "axios@0.30.4"           = "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71"
    "plain-crypto-js@4.2.1"  = "07d889e2dadce6f3910dcbc253317d28ca61c766"
}

# Default scan paths if none provided
if (-not $ScanPaths) {
    # Covers the most common places Windows developers keep Node.js projects
    $ScanPaths = @(
        # Visual Studio / VS Code defaults
        "$env:USERPROFILE\source",
        "$env:USERPROFILE\source\repos",
        # Generic project folder names
        "$env:USERPROFILE\repos",
        "$env:USERPROFILE\projects",
        "$env:USERPROFILE\work",
        "$env:USERPROFILE\dev",
        # Desktop / Documents (some users work here)
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        # OneDrive (personal and corporate)
        "$env:USERPROFILE\OneDrive",
        "$env:ONEDRIVE",
        # Common fixed-drive dev roots
        "C:\dev",
        "C:\projects",
        "C:\work",
        "C:\repos",
        "D:\dev",
        "D:\projects",
        "D:\work",
        "D:\repos",
        # IIS web root
        "C:\inetpub"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    if ($ScanPaths.Count -eq 0) {
        Write-Host "  No common project folders found. Falling back to your user profile: $env:USERPROFILE" -ForegroundColor Yellow
        $ScanPaths = @($env:USERPROFILE)
    }
}

# ── Helpers ────────────────────────────────────────────────────────────────────
$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Get-SHA1Hash {
    param([string]$FilePath)
    try {
        return (Get-FileHash -Path $FilePath -Algorithm SHA1 -ErrorAction Stop).Hash.ToLower()
    } catch { return $null }
}

function Add-Finding {
    param([string]$Category, [string]$Severity, [string]$Detail, [string]$Path = "")
    $obj = [PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Detail   = $Detail
        Path     = $Path
    }
    $findings.Add($obj)

    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "WARNING"  { "Yellow" }
        "INFO"     { "Cyan" }
        default    { "White" }
    }
    Write-Host "  [$Severity] " -ForegroundColor $color -NoNewline
    Write-Host "$Category — $Detail" -ForegroundColor White
    if ($Path) { Write-Host "           Path: $Path" -ForegroundColor DarkGray }
}

# ── Banner ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "║        AXIOS SUPPLY CHAIN ATTACK SCANNER (2026-03-31)          ║" -ForegroundColor Red
Write-Host "║  Compromised: axios@1.14.1 / axios@0.30.4                     ║" -ForegroundColor Red
Write-Host "║  Threat: UNC1069 — WAVESHAPER.V2 RAT                          ║" -ForegroundColor Red
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""
Write-Host "  Scanning $($ScanPaths.Count) path(s):" -ForegroundColor DarkGray
foreach ($p in $ScanPaths) { Write-Host "    • $p" -ForegroundColor DarkGray }
Write-Host "  Git history (Deep): $Deep" -ForegroundColor DarkGray
Write-Host "  Tip: run with -ScanPaths to target specific folders, add -Deep for git history." -ForegroundColor DarkGray
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 1: Find all axios installations in node_modules
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "═══ CHECK 1: Scanning for axios in node_modules ═══" -ForegroundColor Cyan

$axiosFound = 0
foreach ($root in $ScanPaths) {
    Write-Host "  Scanning $root ..." -ForegroundColor DarkGray
    Get-ChildItem -Path $root -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "node_modules[\\/]axios$" } |
        ForEach-Object {
            $axiosFound++
            try {
                $pkg = Get-Content $_.FullName -Raw | ConvertFrom-Json
                $ver = $pkg.version
                if ($BadVersions -contains $ver) {
                    Add-Finding "AXIOS_VERSION" "CRITICAL" "Found compromised axios@$ver" $_.FullName
                } else {
                    Write-Host "  [OK] axios@$ver" -ForegroundColor Green -NoNewline
                    Write-Host " — $($_.FullName)" -ForegroundColor DarkGray
                }
            } catch {
                Add-Finding "AXIOS_VERSION" "WARNING" "Could not parse package.json" $_.FullName
            }
        }
}
if ($axiosFound -eq 0) {
    Write-Host "  No axios installations found in node_modules." -ForegroundColor Green
}
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 2: Scan lockfiles for plain-crypto-js phantom dependency
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "═══ CHECK 2: Scanning lockfiles for phantom dependency ($PhantomDep) ═══" -ForegroundColor Cyan

$lockfilePatterns = @("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb")
foreach ($root in $ScanPaths) {
    foreach ($pattern in $lockfilePatterns) {
        Get-ChildItem -Path $root -Recurse -Filter $pattern -ErrorAction SilentlyContinue |
            Where-Object { $_.DirectoryName -notmatch "node_modules" } |
            ForEach-Object {
                $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                if ($content -and $content -match $PhantomDep) {
                    Add-Finding "LOCKFILE" "CRITICAL" "Lockfile contains '$PhantomDep'" $_.FullName
                }
            }
    }
}
Write-Host "  Lockfile scan complete." -ForegroundColor Green
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 3: Scan for plain-crypto-js in node_modules (may self-delete)
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "═══ CHECK 3: Scanning for plain-crypto-js package ═══" -ForegroundColor Cyan

foreach ($root in $ScanPaths) {
    Get-ChildItem -Path $root -Recurse -Directory -Filter "plain-crypto-js" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "node_modules" } |
        ForEach-Object {
            Add-Finding "PHANTOM_DEP" "CRITICAL" "Found plain-crypto-js in node_modules" $_.FullName
        }
}
Write-Host "  Phantom dependency scan complete (note: malware self-deletes this)." -ForegroundColor Green
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 4: RAT artifact on disk
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "═══ CHECK 4: Checking for RAT artifacts (WAVESHAPER.V2) ═══" -ForegroundColor Cyan

if (Test-Path $RatPath) {
    Add-Finding "RAT_ARTIFACT" "CRITICAL" "RAT payload found at $RatPath (disguised as Windows Terminal)" $RatPath
} else {
    Write-Host "  [OK] No RAT artifact found at $RatPath" -ForegroundColor Green
}

# Also scan recursively for any other wt.exe in ProgramData subdirectories (deduped from above)
Get-ChildItem -Path "$env:PROGRAMDATA" -Recurse -Filter "wt.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $RatPath } |
    ForEach-Object {
        Add-Finding "RAT_ARTIFACT" "CRITICAL" "Suspicious wt.exe found in ProgramData subdirectory" $_.FullName
    }

Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 5: Active C2 connections
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "═══ CHECK 5: Checking for C2 connections ═══" -ForegroundColor Cyan

$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -eq $C2IP }

if ($connections) {
    foreach ($conn in $connections) {
        Add-Finding "C2_CONNECTION" "CRITICAL" "Active connection to C2 $C2IP`:$($conn.RemotePort) (PID: $($conn.OwningProcess))" ""
    }
} else {
    Write-Host "  [OK] No active connections to $C2IP" -ForegroundColor Green
}

# DNS cache check
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match $C2Domain }
    if ($dnsCache) {
        Add-Finding "C2_DNS" "WARNING" "C2 domain '$C2Domain' found in DNS cache" ""
    }
} catch {}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 6 (optional): Git history for traces
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "═══ CHECK 6: Deep scan — git history for '$PhantomDep' ═══" -ForegroundColor Cyan

if ($Deep) {
    foreach ($root in $ScanPaths) {
        Get-ChildItem -Path $root -Recurse -Directory -Filter ".git" -Hidden -ErrorAction SilentlyContinue |
            ForEach-Object {
                $repoDir = $_.Parent.FullName
                Push-Location $repoDir
                try {
                    $gitResult = git log -p --all -- "package-lock.json" "yarn.lock" "package.json" 2>$null |
                        Select-String $PhantomDep
                    if ($gitResult) {
                        Add-Finding "GIT_HISTORY" "WARNING" "Git history contains references to '$PhantomDep'" $repoDir
                    }
                } catch {}
                Pop-Location
            }
    }
    Write-Host "  Git history scan complete." -ForegroundColor Green
} else {
    Write-Host "  Skipped — use -Deep to enable git history scan." -ForegroundColor DarkGray
}
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 7: Global npm installations
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "═══ CHECK 7: Global npm/yarn installations ═══" -ForegroundColor Cyan

try {
    $globalAxios = npm list -g axios --json 2>$null | ConvertFrom-Json
    if ($globalAxios.dependencies.axios.version) {
        $gVer = $globalAxios.dependencies.axios.version
        if ($BadVersions -contains $gVer) {
            Add-Finding "GLOBAL_NPM" "CRITICAL" "Global npm has compromised axios@$gVer" ""
        } else {
            Write-Host "  [OK] Global axios@$gVer" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "  npm not found or no global axios. Skipping." -ForegroundColor DarkGray
}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 8: npm/yarn cache
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "═══ CHECK 8: Checking npm cache ═══" -ForegroundColor Cyan

$npmCachePath = Join-Path $env:APPDATA "npm-cache"
if (Test-Path $npmCachePath) {
    Get-ChildItem -Path $npmCachePath -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match '"name"\s*:\s*"plain-crypto-js"') {
                Add-Finding "NPM_CACHE" "WARNING" "Phantom dependency found in npm cache" $_.FullName
            }
            if ($content -match '"name"\s*:\s*"axios"' -and ($content -match '"version"\s*:\s*"1\.14\.1"' -or $content -match '"version"\s*:\s*"0\.30\.4"')) {
                Add-Finding "NPM_CACHE" "WARNING" "Compromised axios version found in npm cache" $_.FullName
            }
        }

    # Verify any cached tarballs against known-bad SHA1 hashes
    Get-ChildItem -Path $npmCachePath -Recurse -Filter "*.tgz" -ErrorAction SilentlyContinue |
        ForEach-Object {
            $tgz = $_
            foreach ($pkgKey in $BadSHA1.Keys) {
                $pkgName = $pkgKey -replace "@[^@]+$", ""
                if ($tgz.DirectoryName -match [regex]::Escape($pkgName)) {
                    $hash = Get-SHA1Hash $tgz.FullName
                    if ($hash -and $hash -eq $BadSHA1[$pkgKey]) {
                        Add-Finding "NPM_CACHE_HASH" "CRITICAL" "Tarball SHA1 matches known-bad package: $pkgKey" $tgz.FullName
                    }
                }
            }
        }
}
Write-Host "  Cache scan complete." -ForegroundColor Green
Write-Host ""

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║                         SCAN SUMMARY                           ║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor White

$criticals = $findings | Where-Object { $_.Severity -eq "CRITICAL" }
$warnings  = $findings | Where-Object { $_.Severity -eq "WARNING" }

if ($criticals.Count -gt 0) {
    Write-Host ""
    Write-Host "  ██████  COMPROMISED  ██████" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Found $($criticals.Count) CRITICAL finding(s)!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  IMMEDIATE ACTIONS REQUIRED:" -ForegroundColor Yellow
    Write-Host "  1. STOP — Do not just delete files" -ForegroundColor Yellow
    Write-Host "  2. Rotate ALL credentials (npm tokens, SSH keys, API keys, cloud creds)" -ForegroundColor Yellow
    Write-Host "  3. Rotate all database passwords" -ForegroundColor Yellow
    Write-Host "  4. Check CI/CD pipelines for affected installs" -ForegroundColor Yellow
    Write-Host "  5. Block C2: sfrclak.com and 142.11.206.73 at your firewall" -ForegroundColor Yellow
    Write-Host "  6. Rebuild from a clean image if possible" -ForegroundColor Yellow
    Write-Host "  7. Audit git history for unauthorized changes" -ForegroundColor Yellow
} elseif ($warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "  ⚠ WARNINGS FOUND — Review the items above." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "  ✓ CLEAN — No indicators of compromise found." -ForegroundColor Green
}

Write-Host ""
Write-Host "  Total findings: $($findings.Count) (Critical: $($criticals.Count), Warning: $($warnings.Count))" -ForegroundColor White
Write-Host ""

# Export findings to CSV if any
if ($findings.Count -gt 0) {
    $csvPath = Join-Path $PWD "axios-scan-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $findings | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "  Results exported to: $csvPath" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "  Tip: Run with -Deep to also scan git history." -ForegroundColor DarkGray
Write-Host "  Tip: Run with -ScanPaths 'D:\MyRepos','E:\Work' to scan custom paths." -ForegroundColor DarkGray
Write-Host ""

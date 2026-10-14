<#
.SYNOPSIS
    Start the BlueCash mint for development on whatever network the laptop is on now.

.DESCRIPTION
    The laptop's address changes every time it joins a different Wi-Fi network or phone
    hotspot, and the phones hold that address in their own settings. This script removes the
    guesswork: it finds the current IPv4 address, prints the exact URL to type into the app,
    and starts the server on 0.0.0.0 so any interface reaches it.

    It refuses to start without BLUECASH_DATABASE_URL. The mint's identity and denomination
    keys live in the database, and clients pin the mint's public key on first contact, so
    starting against the wrong file silently creates a *different mint* and orphans every
    wallet that has already registered. Falling back to a default is the one convenience
    this script will not offer.

.EXAMPLE
    $env:BLUECASH_DATABASE_URL = "sqlite:///C:/path/to/ble-mint.db"
    .\dev-server.ps1

.EXAMPLE
    .\dev-server.ps1 -Port 8080
#>
[CmdletBinding()]
param(
    [int]$Port = 8000,
    # Only for inspecting the setup: print the address and URL, then exit.
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'

function Write-Field($label, $value) {
    Write-Host ("  {0,-16} " -f $label) -NoNewline -ForegroundColor DarkGray
    Write-Host $value
}

# --- the database must be chosen deliberately -------------------------------------------
$dbUrl = $env:BLUECASH_DATABASE_URL
if ([string]::IsNullOrWhiteSpace($dbUrl)) {
    Write-Host ""
    Write-Host "  BLUECASH_DATABASE_URL is not set." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Refusing to start. Without it the server would create a fresh database," -ForegroundColor Yellow
    Write-Host "  which means a new mint identity -- every wallet that already registered" -ForegroundColor Yellow
    Write-Host "  pins the old key and would refuse this one." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Set it to the database you mean to serve, for example:"
    Write-Host '    $env:BLUECASH_DATABASE_URL = "sqlite:///C:/full/path/to/ble-mint.db"' -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# For a SQLite URL, say plainly whether the file is there. A missing file is not an error --
# that is how a new mint is created -- but it should never be a surprise.
$isNew = $false
if ($dbUrl -match '^sqlite:///(.+)$') {
    $dbPath = $Matches[1]
    $isNew = -not (Test-Path -LiteralPath $dbPath)
}

# --- find the address the phones should use ---------------------------------------------
$candidates = Get-NetIPConfiguration |
    Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address } |
    ForEach-Object {
        [pscustomobject]@{
            Interface = $_.InterfaceAlias
            Address   = $_.IPv4Address.IPAddress
            Gateway   = ($_.IPv4DefaultGateway.NextHop -join ',')
        }
    } |
    Where-Object { $_.Address -notlike '127.*' -and $_.Address -notlike '169.254.*' }

if (-not $candidates) {
    Write-Host ""
    Write-Host "  No usable IPv4 address found." -ForegroundColor Red
    Write-Host "  Join a Wi-Fi network or a phone hotspot first, then run this again."
    Write-Host ""
    exit 1
}

# Prefer an interface with a default gateway: on a hotspot that is the one carrying traffic.
$chosen = @($candidates | Where-Object { $_.Gateway })[0]
if (-not $chosen) { $chosen = @($candidates)[0] }
$baseUrl = "http://$($chosen.Address):$Port"

Write-Host ""
Write-Host "  BlueCash mint -- development server" -ForegroundColor Cyan
Write-Host ""
Write-Field "interface" $chosen.Interface
Write-Field "laptop IPv4" $chosen.Address
Write-Field "listening on" "0.0.0.0:$Port  (all interfaces)"
Write-Field "database" $dbUrl
if ($isNew) {
    Write-Host "                   this file does not exist yet -- a NEW mint will be created" -ForegroundColor Yellow
}

if ($candidates.Count -gt 1) {
    Write-Host ""
    Write-Host "  Other addresses on this machine (use one of these if the phones cannot reach the first):" -ForegroundColor DarkGray
    $candidates | Where-Object { $_.Address -ne $chosen.Address } | ForEach-Object {
        Write-Host ("    {0,-15} {1}" -f $_.Address, $_.Interface) -ForegroundColor DarkGray
    }
}

# --- which mint is in that database? ------------------------------------------------------
# Read straight from the file, read-only, so the fingerprint is known before anything starts.
# Compare it with the one the phones registered against: if it differs, they will refuse this
# server with "the mint's signing key changed".
$python = Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe'
if (-not $isNew -and $dbUrl -match '^sqlite:///(.+)$' -and (Test-Path -LiteralPath $python)) {
    $reader = @'
import hashlib, sqlite3, sys
try:
    c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1].replace("?", "%3f"), uri=True)
    row = c.execute("select public_key_hex from mint_identity where id = 1").fetchone()
    print(hashlib.sha256(row[0].encode()).hexdigest()[:16] if row else "none yet")
except Exception as e:
    print("unreadable (%s)" % type(e).__name__)
'@
    # Piped to stdin rather than passed with -c: a multi-line program does not survive
    # PowerShell's argument handling.
    $fingerprint = $reader | & $python - $dbPath 2>$null
    if ($fingerprint) { Write-Field "mint fingerprint" $fingerprint.Trim() }
}

Write-Host ""
Write-Host "  Enter this in the app, under Settings -> Backend:" -ForegroundColor Green
Write-Host "      $baseUrl" -ForegroundColor Green -BackgroundColor Black
Write-Host ""
Write-Host "  Check it from a phone with:" -ForegroundColor DarkGray
Write-Host "      adb -s <serial> shell curl -s -m 8 $baseUrl/health" -ForegroundColor DarkGray
Write-Host ""

if ($WhatIfOnly) { exit 0 }

# --- start the server --------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $python)) {
    Write-Host "  Interpreter not found at $python" -ForegroundColor Red
    Write-Host "  Create the virtual environment first, or run uvicorn yourself."
    exit 1
}

Push-Location $PSScriptRoot
try {
    & $python -m uvicorn app.main:app --host 0.0.0.0 --port $Port
}
finally {
    Pop-Location
}

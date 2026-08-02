# setup.ps1 - one-time setup. Run this once, then use mnemosyne.cmd.
# Creates a private Python environment in this folder (.venv) and installs what Mnemosyne needs.
# Safe to re-run if something goes wrong partway through.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Mnemosyne setup starting..." -ForegroundColor Cyan

# Find a Python 3 interpreter.
$py = $null
foreach ($candidate in @("py -3", "python3", "python")) {
    $cmd = ($candidate -split " ")[0]
    $extraArg = if ($candidate -match " ") { ($candidate -split " ")[1] } else { $null }
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        try {
            if ($extraArg) { & $cmd $extraArg --version 2>&1 | Out-Null } else { & $cmd --version 2>&1 | Out-Null }
            if ($LASTEXITCODE -eq 0) { $py = $candidate; break }
        } catch { }
    }
}
if (-not $py) {
    Write-Host ""
    Write-Host "Could not find Python on this computer." -ForegroundColor Red
    Write-Host "Install Python 3.11 or newer from https://www.python.org/downloads/ (check the box"
    Write-Host "that says 'Add python.exe to PATH' during install), then run this script again."
    exit 1
}
Write-Host "Found Python: $py"

Write-Host "Creating a private environment in .venv (this is normal, only takes a few seconds)..."
$pyCmd, $pyArg = $py -split " ", 2
if ($pyArg) { & $pyCmd $pyArg -m venv "$here\.venv" } else { & $pyCmd -m venv "$here\.venv" }
if ($LASTEXITCODE -ne 0) { Write-Host "Failed to create the environment." -ForegroundColor Red; exit 1 }

Write-Host "Installing what Mnemosyne needs (this can take a minute or two, it's downloading things)..."
& "$here\.venv\Scripts\python.exe" -m pip install -q -r "$here\requirements.txt"
if ($LASTEXITCODE -ne 0) { Write-Host "Something went wrong installing dependencies. See the error above." -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "Done! Mnemosyne is set up." -ForegroundColor Green
Write-Host ""
Write-Host "Try it:"
Write-Host "  .\mnemosyne.cmd status"
Write-Host ""
Write-Host "The first real query or ingest will download a small local AI model (~130MB, one time,"
Write-Host "needs internet); after that everything runs fully offline."
Write-Host ""
Write-Host "Want Claude to use this automatically in conversation? Copy the 'skill' folder into:"
Write-Host "  $env:USERPROFILE\.claude\skills\mnemosyne\"
Write-Host "(see README.md for the full walkthrough)"

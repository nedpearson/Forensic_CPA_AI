<#
.SYNOPSIS
Wrapper script to reliably execute the Demo environment seeder.

.DESCRIPTION
Activates the virtual environment safely from any directory, invokes
the Python demo seeder script to populate idempotent dummy data, 
and returns the terminal to normal state.
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir

# Activate Virtual Environment
$VenvActivate = Join-Path $RepoRoot ".venv\Scripts\Activate.ps1"
if (Test-Path $VenvActivate) {
    Write-Host "Activating virtual environment..." -ForegroundColor Cyan
    . $VenvActivate
}
else {
    Write-Warning "Virtual environment not found at .venv. Will attempt to run using system Python."
}

# Run the Python seed script
$SeedScript = Join-Path $ScriptDir "seed_demo.py"
Write-Host "Running $SeedScript..." -ForegroundColor Yellow

# Force Python into unbuffered mode so print() outputs immediately in PowerShell
$env:PYTHONUNBUFFERED = 1
python $SeedScript

# Deactivate Virtual Environment safely if it exists
if (Get-Command deactivate -ErrorAction SilentlyContinue) {
    deactivate
}

Write-Host "Seed completed." -ForegroundColor Green

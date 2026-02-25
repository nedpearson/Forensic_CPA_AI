$ErrorActionPreference = "Stop"

# Clear screen for a fresh start
Clear-Host

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Starting Forensic CPA AI Environment" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $PSScriptRoot

$PORT = 3004
$URL = "http://localhost:$PORT"

# 1. Check and Create Virtual Environment
if (!(Test-Path ".\.venv\Scripts\Activate.ps1")) {
    Write-Host "Creating Python virtual environment..." -ForegroundColor Yellow
    try {
        py -m venv .venv
    } catch {
        python -m venv .venv
    }
}

# 2. Activate Virtual Environment
Write-Host "Activating virtual environment..." -ForegroundColor Green
. ".\.venv\Scripts\Activate.ps1"

# 3. Upgrade Pip & Install Requirements
Write-Host "Installing/Verifying dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
Write-Host "Dependencies installed successfully." -ForegroundColor Green
Write-Host ""

# 4. Check if port is already in use
$portInUse = Get-NetTCPConnection -LocalPort $PORT -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "Port $PORT is currently in use. Attempting to free it..." -ForegroundColor Yellow
    try {
        $blockingProcess = Get-Process -Id $portInUse.OwningProcess -ErrorAction SilentlyContinue
        if ($blockingProcess -and $blockingProcess.Name -eq "python") {
            Stop-Process -Id $portInUse.OwningProcess -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Write-Host "Freed port $PORT." -ForegroundColor Green
        } else {
             Write-Host "Warning: Port $PORT is used by a non-Python process. The app might fail to start." -ForegroundColor Red
        }
    } catch {
        Write-Host "Warning: Could not free port $PORT." -ForegroundColor Red
    }
}

# 5. Launch Browser in background
Write-Host "Launching Browser to $URL..." -ForegroundColor Cyan
Start-Job -ScriptBlock {
    param($url)
    Start-Sleep -Seconds 3
    Start-Process $url
} -ArgumentList $URL | Out-Null

# 6. Start the App
Write-Host "Starting Flask Server on port $PORT..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
Write-Host ""
python .\app.py --port=$PORT

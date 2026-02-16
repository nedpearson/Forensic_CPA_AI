# Forensic CPA AI - Windows Start Script
# Must be run as: powershell -NoProfile -ExecutionPolicy Bypass -File .\start.ps1

[CmdletBinding()]
param(
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

# Get repo root from script location
if (-not $PSCommandPath) {
    Write-Error "This script must be run as a .ps1 file, not copy-pasted into PowerShell."
    exit 1
}
$RepoRoot = Split-Path -Parent $PSCommandPath
Set-Location $RepoRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  FORENSIC CPA AI - Your Financial Private Investigator" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check for logs directory
if (-not (Test-Path ".\logs")) {
    New-Item -ItemType Directory -Path ".\logs" | Out-Null
    Write-Host "[OK] Created logs directory" -ForegroundColor Green
}

$LogFile = ".\logs\forensic_cpa_ai.log"
$PidFile = ".\.forensic_cpa_ai.pid"

# Stop any existing instance
if (Test-Path $PidFile) {
    $OldPid = Get-Content $PidFile -Raw
    if ($OldPid -match '^\d+$') {
        $OldPid = [int]$OldPid
        $Process = Get-Process -Id $OldPid -ErrorAction SilentlyContinue
        if ($Process) {
            Write-Host "[INFO] Stopping existing instance (PID: $OldPid)..." -ForegroundColor Yellow
            Stop-Process -Id $OldPid -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

# Free port if occupied
Write-Host "[INFO] Checking if port $Port is free..." -ForegroundColor Yellow
$Listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($Listener) {
    $OwningPid = $Listener.OwningProcess
    Write-Host "[WARN] Port $Port is occupied by PID $OwningPid. Stopping it..." -ForegroundColor Yellow
    Stop-Process -Id $OwningPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Ensure Python is available
$PythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $PythonCmd = $cmd
        break
    }
}

if (-not $PythonCmd) {
    Write-Error "Python is not installed or not in PATH. Please install Python 3.11+ from https://www.python.org/downloads/"
    exit 1
}

$PythonVersion = & $PythonCmd --version 2>&1
Write-Host "[OK] Found Python: $PythonVersion" -ForegroundColor Green

# Check if virtual environment exists
if (-not (Test-Path ".\.venv\Scripts\Activate.ps1")) {
    Write-Host "[INFO] Creating Python virtual environment..." -ForegroundColor Yellow
    & $PythonCmd -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create virtual environment"
        exit 1
    }
    Write-Host "[OK] Virtual environment created" -ForegroundColor Green
}

# Activate virtual environment
Write-Host "[INFO] Activating virtual environment..." -ForegroundColor Yellow
& .\.venv\Scripts\Activate.ps1

# Install/upgrade dependencies
Write-Host "[INFO] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
& python -m pip install --upgrade pip --quiet
& pip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install dependencies"
    exit 1
}
Write-Host "[OK] Dependencies installed" -ForegroundColor Green

# Try waitress first (production), fallback to Flask dev server
$UseWaitress = $false
try {
    & pip show waitress | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $UseWaitress = $true
    }
} catch {
    $UseWaitress = $false
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Starting Forensic CPA AI on port $Port..." -ForegroundColor Cyan
Write-Host "  URL: http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host "  Logs: $LogFile" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Start the server in background
if ($UseWaitress) {
    Write-Host "[INFO] Using Waitress WSGI server (production)" -ForegroundColor Green
    $StartCmd = "python -m waitress --host=0.0.0.0 --port=$Port wsgi:application"
} else {
    Write-Host "[WARN] Using Flask development server (waitress not found)" -ForegroundColor Yellow
    $env:PORT = $Port
    $StartCmd = "python app.py"
}

# Start process and capture PID
$ProcessInfo = Start-Process -FilePath "python" -ArgumentList "-c", "import subprocess, sys; sys.exit(subprocess.call('$StartCmd', shell=True))" -PassThru -WindowStyle Hidden -RedirectStandardOutput $LogFile -RedirectStandardError $LogFile -NoNewWindow
Start-Sleep -Seconds 1

# Alternative: use direct command
if ($UseWaitress) {
    $Process = Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "-m", "waitress", "--host=0.0.0.0", "--port=$Port", "wsgi:application" -PassThru -WindowStyle Hidden -RedirectStandardOutput $LogFile -RedirectStandardError $LogFile
} else {
    $env:PORT = $Port
    $Process = Start-Process -FilePath ".\.venv\Scripts\python.exe" -ArgumentList "app.py" -PassThru -WindowStyle Hidden -RedirectStandardOutput $LogFile -RedirectStandardError $LogFile
}

if (-not $Process) {
    Write-Error "Failed to start server process"
    exit 1
}

$Pid = $Process.Id
Set-Content -Path $PidFile -Value $Pid
Write-Host "[OK] Server started with PID: $Pid" -ForegroundColor Green

# Wait for server to start
Write-Host "[INFO] Waiting for server to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Health check
$HealthUrl = "http://127.0.0.1:$Port/health"
$MaxRetries = 10
$Success = $false

for ($i = 1; $i -le $MaxRetries; $i++) {
    try {
        $Response = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($Response.StatusCode -eq 200) {
            $Success = $true
            break
        }
    } catch {
        # Retry
    }
    Start-Sleep -Seconds 1
}

Write-Host ""
if ($Success) {
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  SUCCESS! Forensic CPA AI is running" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  URL: http://127.0.0.1:$Port" -ForegroundColor White
    Write-Host "  Health: $HealthUrl" -ForegroundColor White
    Write-Host "  PID: $Pid" -ForegroundColor White
    Write-Host "  Logs: $LogFile" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Open your browser to: http://127.0.0.1:$Port" -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  WARNING: Server started but health check failed" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  The server may still be starting up. Please check:" -ForegroundColor Yellow
    Write-Host "  1. Logs: $LogFile" -ForegroundColor White
    Write-Host "  2. URL: http://127.0.0.1:$Port" -ForegroundColor White
    Write-Host "  3. Process: Get-Process -Id $Pid" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor Red
}

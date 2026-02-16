# Forensic CPA AI - Windows Stop Script
# Must be run as: powershell -NoProfile -ExecutionPolicy Bypass -File .\stop.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Get repo root from script location
if (-not $PSCommandPath) {
    Write-Error "This script must be run as a .ps1 file, not copy-pasted into PowerShell."
    exit 1
}
$RepoRoot = Split-Path -Parent $PSCommandPath
Set-Location $RepoRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  FORENSIC CPA AI - Stopping Server" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$PidFile = ".\.forensic_cpa_ai.pid"

# Check if PID file exists
if (-not (Test-Path $PidFile)) {
    Write-Host "[WARN] PID file not found. Checking for running processes..." -ForegroundColor Yellow

    # Try to find Python processes running app.py or wsgi.py
    $Processes = Get-Process -Name python* -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*app.py*" -or $_.CommandLine -like "*wsgi*" -or $_.CommandLine -like "*waitress*"
    }

    if ($Processes) {
        Write-Host "[INFO] Found $($Processes.Count) potential Forensic CPA AI process(es)" -ForegroundColor Yellow
        foreach ($Process in $Processes) {
            Write-Host "[INFO] Stopping PID: $($Process.Id)" -ForegroundColor Yellow
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
        Write-Host "[OK] Stopped all potential processes" -ForegroundColor Green
    } else {
        Write-Host "[INFO] No running processes found" -ForegroundColor Green
    }

    Write-Host ""
    exit 0
}

# Read PID from file
$Pid = Get-Content $PidFile -Raw
if (-not ($Pid -match '^\d+$')) {
    Write-Host "[ERROR] Invalid PID in file: $Pid" -ForegroundColor Red
    Remove-Item $PidFile -Force
    exit 1
}

$Pid = [int]$Pid

# Check if process is running
$Process = Get-Process -Id $Pid -ErrorAction SilentlyContinue

if (-not $Process) {
    Write-Host "[WARN] Process with PID $Pid is not running (may have crashed)" -ForegroundColor Yellow
    Remove-Item $PidFile -Force
    Write-Host "[OK] Cleaned up stale PID file" -ForegroundColor Green
} else {
    Write-Host "[INFO] Stopping process with PID: $Pid" -ForegroundColor Yellow
    Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue

    # Wait for process to exit
    $MaxWait = 5
    for ($i = 1; $i -le $MaxWait; $i++) {
        Start-Sleep -Seconds 1
        $Process = Get-Process -Id $Pid -ErrorAction SilentlyContinue
        if (-not $Process) {
            break
        }
    }

    if (Get-Process -Id $Pid -ErrorAction SilentlyContinue) {
        Write-Host "[WARN] Process did not stop gracefully. Force killing..." -ForegroundColor Yellow
        Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
    }

    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Server stopped successfully" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Forensic CPA AI has been stopped" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

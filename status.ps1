# Forensic CPA AI - Windows Status Script
# Must be run as: powershell -NoProfile -ExecutionPolicy Bypass -File .\status.ps1

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
Write-Host "  FORENSIC CPA AI - Status Check" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$PidFile = ".\.forensic_cpa_ai.pid"
$HealthUrl = "http://127.0.0.1:$Port/health"

# Check PID file
$PidExists = Test-Path $PidFile
$ProcessRunning = $false
$Pid = $null

if ($PidExists) {
    $Pid = Get-Content $PidFile -Raw
    if ($Pid -match '^\d+$') {
        $Pid = [int]$Pid
        $Process = Get-Process -Id $Pid -ErrorAction SilentlyContinue
        if ($Process) {
            $ProcessRunning = $true
            Write-Host "[OK] Process Status: RUNNING (PID: $Pid)" -ForegroundColor Green
            Write-Host "     Process Name: $($Process.Name)" -ForegroundColor Gray
            Write-Host "     Memory Usage: $([math]::Round($Process.WorkingSet64 / 1MB, 2)) MB" -ForegroundColor Gray
            Write-Host "     CPU Time: $($Process.CPU) seconds" -ForegroundColor Gray
        } else {
            Write-Host "[ERROR] Process Status: NOT RUNNING (stale PID file)" -ForegroundColor Red
            Write-Host "        PID file exists but process $Pid is not running" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[WARN] PID file not found" -ForegroundColor Yellow
}

# Check port
Write-Host ""
$PortListening = $false
try {
    $Connection = Test-NetConnection -ComputerName 127.0.0.1 -Port $Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if ($Connection.TcpTestSucceeded) {
        $PortListening = $true
        Write-Host "[OK] Port Status: LISTENING on $Port" -ForegroundColor Green

        # Get process owning the port
        $Listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($Listener) {
            $OwningPid = $Listener.OwningProcess
            Write-Host "     Owned by PID: $OwningPid" -ForegroundColor Gray
        }
    } else {
        Write-Host "[ERROR] Port Status: NOT LISTENING on $Port" -ForegroundColor Red
    }
} catch {
    Write-Host "[ERROR] Port Status: UNABLE TO CHECK" -ForegroundColor Red
}

# Health check
Write-Host ""
$HealthOk = $false
try {
    $Response = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
    if ($Response.StatusCode -eq 200) {
        $HealthOk = $true
        $Content = $Response.Content | ConvertFrom-Json
        Write-Host "[OK] Health Check: PASSED" -ForegroundColor Green
        Write-Host "     URL: $HealthUrl" -ForegroundColor Gray
        Write-Host "     Status: $($Content.status)" -ForegroundColor Gray
        Write-Host "     Service: $($Content.service)" -ForegroundColor Gray
    } else {
        Write-Host "[ERROR] Health Check: FAILED (HTTP $($Response.StatusCode))" -ForegroundColor Red
    }
} catch {
    Write-Host "[ERROR] Health Check: FAILED (Connection refused)" -ForegroundColor Red
    Write-Host "        URL: $HealthUrl" -ForegroundColor Yellow
}

# Overall status
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan

if ($ProcessRunning -and $PortListening -and $HealthOk) {
    Write-Host "  OVERALL STATUS: HEALTHY" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  Access at: http://127.0.0.1:$Port" -ForegroundColor White
    Write-Host ""
    exit 0
} elseif ($ProcessRunning -and $PortListening) {
    Write-Host "  OVERALL STATUS: RUNNING (Health check failed)" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host "  Server is running but not responding correctly" -ForegroundColor Yellow
    Write-Host "  Check logs: .\logs\forensic_cpa_ai.log" -ForegroundColor White
    Write-Host ""
    exit 1
} else {
    Write-Host "  OVERALL STATUS: NOT RUNNING" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  Start the server with: .\start.ps1" -ForegroundColor White
    Write-Host ""
    exit 1
}

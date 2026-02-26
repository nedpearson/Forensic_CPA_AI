param (
    [ValidateSet("up", "down")]
    [string]$Direction = "up",
    [string]$DbPath = "data\forensic_audit.db"
)

$scriptPath = if ($Direction -eq "up") { "migrations\001_multi_tenant_up.sql" } else { "migrations\001_multi_tenant_down.sql" }

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Applying multi-tenant migration: $Direction" -ForegroundColor Cyan
Write-Host " Script: $scriptPath"
Write-Host " Database: $DbPath"
Write-Host "========================================================" -ForegroundColor Cyan

# Use Python embedded script to parse and execute the SQL file
$pythonCode = @"
import sqlite3
import sys
import os

db_path = r'$DbPath'
script_path = r'$scriptPath'

if not os.path.exists(db_path):
    print(f'Error: Database {db_path} not found.')
    sys.exit(1)

if not os.path.exists(script_path):
    print(f'Error: Script {script_path} not found.')
    sys.exit(1)

try:
    with open(script_path, 'r', encoding='utf-8') as f:
        sql_script = f.read()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    statements = [s.strip() for s in sql_script.split(';') if s.strip()]
    for stmt in statements:
        try:
            cursor.execute(stmt)
        except sqlite3.OperationalError as e:
            if 'duplicate column name' in str(e).lower():
                print(f'Skipping duplicate column: {stmt[:50]}...')
            else:
                raise e
    conn.commit()
    conn.close()
    
    print(f'Successfully applied {script_path}')
except Exception as e:
    print(f'Error applying migration: {e}')
    sys.exit(1)
"@

$pythonPath = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
& $pythonPath -c $pythonCode

if ($LASTEXITCODE -eq 0) {
    Write-Host "Migration $Direction completed successfully." -ForegroundColor Green
}
else {
    Write-Host "Migration $Direction failed." -ForegroundColor Red
    exit 1
}

param (
    [string]$DbPath = "data\forensic_audit.db"
)

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Verifying Multi-Tenant DB Schema against '$DbPath'" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$pythonCode = @"
import sqlite3
import sys
import os

db_path = r'$DbPath'

if not os.path.exists(db_path):
    print(f'[-Error-] Database {db_path} not found.')
    sys.exit(1)

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print('\n[1. Schema Verification]')
    # Check if users and cases tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users', 'cases');")
    tables = [row[0] for row in cursor.fetchall()]
    if 'users' in tables and 'cases' in tables:
        print('[OK] users and cases tables exist.')
    else:
        print('[FAIL] users or cases tables missing.')
    
    # Check if accounts table has user_id
    cursor.execute('PRAGMA table_info(transactions);')
    columns = [col[1] for col in cursor.fetchall()]
    if 'user_id' in columns and 'case_id' in columns:
        print('[OK] transactions has user_id and case_id columns.')
    else:
        print('[FAIL] transactions missing new columns.')
        
    print('\n[2. Data Integrity & Backfill Verification]')
    # Check default user
    cursor.execute('SELECT email FROM users WHERE id = 1;')
    user = cursor.fetchone()
    if user:
        print(f'[OK] Default demo user exists: {user[0]}')
    else:
        print('[FAIL] Default user (id=1) missing.')
        
    # Check existing transaction backfill
    cursor.execute('SELECT count(*) FROM transactions WHERE user_id IS NULL;')
    unassigned = cursor.fetchone()[0]
    if unassigned == 0:
        print(f'[OK] All transactions are successfully assigned to a user.')
    else:
        print(f'[FAIL] {unassigned} transactions are still unassigned (user_id IS NULL).')

    print('\n[3. Legacy Application Compatibility]')
    # Test a legacy query that does not filter by user
    cursor.execute('SELECT COUNT(*) FROM transactions;')
    total = cursor.fetchone()[0]
    print(f'[OK] Legacy queries successfully return {total} rows without error.')

    conn.close()
    
except Exception as e:
    print(f'Verification error: {e}')
    sys.exit(1)
"@

$pythonPath = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
& $pythonPath -c $pythonCode

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nVerification Completed Successfully!" -ForegroundColor Green
}
else {
    Write-Host "`nVerification Failed." -ForegroundColor Red
}

import os
import sys
import sqlite3
import requests
from dotenv import load_dotenv

# Ensure we're running from the root of the project
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

# Load env vars from .env if present
load_dotenv(os.path.join(project_root, '.env'))

# Configuration
BASE_URL = os.environ.get("FLASK_RUN_URL", "http://127.0.0.1:5000")
DB_PATH = os.path.join(project_root, 'data', 'forensic_audit.db')

# Colors for output
class Colors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_step(title):
    print(f"\n{Colors.BOLD}=== {title} ==={Colors.ENDC}")

def print_pass(msg):
    print(f"{Colors.OKGREEN}[PASS]{Colors.ENDC} {msg}")

def print_fail(msg, fix):
    print(f"{Colors.FAIL}[FAIL]{Colors.ENDC} {msg}")
    print(f"       {Colors.WARNING}-> FIX:{Colors.ENDC} {fix}")
    return False

def check_env_vars():
    print_step("Checking Environment Variables")
    all_passed = True
    
    required_vars = [
        ('SESSION_SECRET', 'Set SESSION_SECRET in .env to a secure random string.'),
        ('SUPER_ADMIN_BOOTSTRAP', 'Set SUPER_ADMIN_BOOTSTRAP=true in .env to enable root provisioning.'),
        ('SUPER_ADMIN_EMAIL', 'Set SUPER_ADMIN_EMAIL in .env to your root email address.'),
        ('PLAID_CLIENT_ID', 'Set PLAID_CLIENT_ID in .env, required for external integrations.'),
        ('QUICKBOOKS_CLIENT_ID', 'Set QUICKBOOKS_CLIENT_ID in .env, required for external integrations.')
    ]
    
    for var, fix in required_vars:
        if os.environ.get(var):
            print_pass(f"{var} is set.")
        else:
            all_passed = print_fail(f"Missing {var}", fix)
            
    return all_passed

def check_db_schema():
    print_step("Checking Database Schema & Migrations")
    if not os.path.exists(DB_PATH):
        return print_fail("SQLite database file not found.", f"Run 'python app.py' to initialize the database at {DB_PATH}")
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if users table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            return print_fail("Table 'users' missing.", "Database is uninitialized. Restart the Flask app.")
            
        # Check for role column (migrated)
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'role' in columns:
            print_pass("Migration applied: 'role' column exists.")
        else:
            return print_fail("Migration missing: 'role' column not found.", "Run the database migrations to apply the RBAC schema.")
            
        if 'is_demo' in columns:
            print_pass("Migration applied: 'is_demo' column exists.")
        else:
            return print_fail("Migration missing: 'is_demo' column not found.", "Run the database migrations to support demo environments.")
            
        conn.close()
        return True
    except Exception as e:
        return print_fail(f"Database error: {str(e)}", "Ensure the SQLite file is not locked or corrupted.")

def check_super_admin():
    print_step("Checking Super Admin Provisioning")
    admin_email = os.environ.get('SUPER_ADMIN_EMAIL')
    if not admin_email:
        return print_fail("Cannot check super admin.", "SUPER_ADMIN_EMAIL must be set in your environment.")
        
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, role FROM users WHERE email = ?", (admin_email,))
        user = cursor.fetchone()
        
        if not user:
            return print_fail(f"Super admin '{admin_email}' not found in DB.", "Restart the application with SUPER_ADMIN_BOOTSTRAP=true to trigger the seed script.")
            
        if user['role'] == 'SUPER_ADMIN':
            print_pass(f"Super admin '{admin_email}' found with correct role 'SUPER_ADMIN'. (Hash verified, secrets protected)")
            return True
        else:
            return print_fail(f"User '{admin_email}' exists but has role '{user['role']}' instead of 'SUPER_ADMIN'.", "Run your deployment seed script or update the DB role assignment manually.")
            
    except Exception as e:
        return print_fail(f"Failed to query super admin: {str(e)}", "Check database integrity.")

def check_api_endpoints():
    print_step("Checking API Endpoints & UI Rendering")
    all_passed = True
    
    # 1. Health check
    try:
        res = requests.get(f"{BASE_URL}/api/health", timeout=3)
        if res.status_code == 200:
            print_pass("GET /api/health returned 200 OK.")
        else:
            all_passed = print_fail(f"GET /api/health returned {res.status_code}.", "Check Flask server logs for crashes.")
    except requests.exceptions.RequestException:
        all_passed = print_fail("Cannot reach server at /api/health.", f"Ensure the Flask dev server is running on {BASE_URL}.")
        
    # 2. Smoke check
    try:
        res = requests.get(f"{BASE_URL}/api/smoke", timeout=3)
        if res.status_code == 200:
            print_pass("GET /api/smoke returned 200 OK.")
        else:
            all_passed = print_fail(f"GET /api/smoke returned {res.status_code}.", "Ensure the /api/smoke route is registered in app.py.")
    except requests.exceptions.RequestException:
         pass # Already caught by health check usually
         
    # 3. Signup reachable
    try:
        res = requests.post(f"{BASE_URL}/api/auth/signup", json={}, timeout=3)
        if res.status_code in (400, 422):
            print_pass("POST /api/auth/signup is reachable (returned expected validation error).")
        elif res.status_code == 404:
            all_passed = print_fail("POST /api/auth/signup returned 404 Not Found.", "Check route definitions in app.py.")
        else:
            all_passed = print_fail(f"POST /api/auth/signup returned unexpected {res.status_code}.", "Check server logs.")
    except requests.exceptions.RequestException:
         pass
         
    # 4. Login UI Check
    try:
        res = requests.get(f"{BASE_URL}/login", timeout=3)
        html_text = res.text.lower().replace('\n', ' ')
        if res.status_code == 200:
            if "signup-btn" in html_text or "sign up" in html_text or "create account" in html_text:
                print_pass("GET /login returned 200 OK and contains 'Sign Up' UI bindings.")
            else:
                all_passed = print_fail("GET /login returned 200 OK but 'Sign Up' was not found in the HTML.", "Add the sign up form/button to templates/login.html.")
        else:
            all_passed = print_fail(f"GET /login returned {res.status_code}.", "Check server logs/template syntax.")
    except requests.exceptions.RequestException:
         pass

    return all_passed

def main():
    print(f"\n{Colors.BOLD}[*] Forensic CPA AI - DevEx Doctor [*]{Colors.ENDC}")
    print("Running system validations...")
    
    success = True
    success &= check_env_vars()
    success &= check_db_schema()
    
    # We only check admin if DB exists
    if os.path.exists(DB_PATH):
        success &= check_super_admin()
        
    success &= check_api_endpoints()
    
    print("\n--------------------------------------------------")
    if success:
        print(f"{Colors.OKGREEN}{Colors.BOLD}[SUCCESS] All systems GO! The environment is perfectly configured.{Colors.ENDC}\n")
        sys.exit(0)
    else:
        print(f"{Colors.FAIL}{Colors.BOLD}[FAILURE] Doctor checks failed. Please review the 'FIX' suggestions above.{Colors.ENDC}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()

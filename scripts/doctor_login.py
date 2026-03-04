import os
import sys
import time
import requests
import subprocess
import threading
from dotenv import load_dotenv

# Ensure we have the base project path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def print_step(msg):
    print(f"{YELLOW}[*] {msg}{RESET}")

def print_pass(msg):
    print(f"{GREEN}[PASS] {msg}{RESET}")

def print_fail(msg):
    print(f"{RED}[x] {msg}{RESET}")
    print(f"\n{RED}=== DOCTOR VERIFICATION FAILED ==={RESET}")
    sys.exit(1)

def main():
    print(f"\n=== FORENSIC CPA AI - SUPER ADMIN DOCTOR ===\n")
    
    # 1. Validate Env Vars
    print_step("Validating environment variables...")
    load_dotenv(os.path.join(PROJECT_ROOT, '.env'))
    
    email = os.environ.get('SUPER_ADMIN_EMAIL', 'nedpearson@gmail.com')
    password = os.environ.get('SUPER_ADMIN_PASSWORD')
    bootstrap_enabled = os.environ.get('ENABLE_SUPER_ADMIN_BOOTSTRAP', 'false').lower() in ('true', '1')

    if not password:
        print_fail("SUPER_ADMIN_PASSWORD is not set in .env")
    if not bootstrap_enabled:
        print_fail("ENABLE_SUPER_ADMIN_BOOTSTRAP is not enabled in .env")
        
    print_pass(f"Env vars valid. Target: {email}")

    # 2. Run Super-Admin Bootstrap
    print_step("Running database bootstrap override...")
    try:
        from database import init_db
        init_db()
        print_pass("Bootstrap routine executed successfully.")
    except Exception as e:
        print_fail(f"Bootstrap failed: {e}")

    # 3. Start Server (if not running)
    print_step("Starting isolated server instance for tests...")
    base_url = "http://127.0.0.1:5001"
    server_process = None
    
    env = os.environ.copy()
    env['PYTHONPATH'] = PROJECT_ROOT
    env['FLASK_RUN_PORT'] = '5001'
    env['FLASK_APP'] = 'app.py'
    
    try:
        server_process = subprocess.Popen(
            [sys.executable, '-m', 'flask', 'run', '--port', '5001', '--no-reload'],
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )
        
        # Wait for server to boot
        max_retries = 15
        server_up = False
        for i in range(max_retries):
            try:
                requests.get(f"{base_url}/health", timeout=1)
                server_up = True
                break
            except requests.ConnectionError:
                time.sleep(1)
                
        if not server_up:
            if server_process:
                server_process.kill()
            print_fail("Timed out waiting for isolated server to start.")
            
        print_pass("Ephemeral isolated server started successfully on port 5001.")
    except Exception as e:
        print_fail(f"Failed to spawn isolated server: {e}")

    # 4. Perform POST /api/auth/login
    print_step(f"Attempting login as {email}...")
    session = requests.Session()
    login_url = f"{base_url}/api/auth/login"
    
    try:
        res = session.post(login_url, json={
            "email": email,
            "password": password
        }, timeout=5)
        
        if res.status_code != 200:
            print_fail(f"Login rejected with status {res.status_code}: {res.text}")
            
        data = res.json()
        if data.get("status") != "success":
            print_fail(f"Login payload failed: {data}")
            
        print_pass("Login endpoint returned success.")
    except Exception as e:
        if server_process:
            server_process.kill()
        print_fail(f"Login request threw exception: {e}")

    # 5. Confirm role == SUPER_ADMIN
    print_step("Validating authenticated session role...")
    try:
        me_url = f"{base_url}/api/auth/me"
        me_res = session.get(me_url, timeout=5)
        
        if me_res.status_code != 200:
            print_fail(f"/api/auth/me rejected session with status {me_res.status_code}")
            
        me_data = me_res.json()
        role = me_data.get('role')
        
        if role != 'SUPER_ADMIN':
            print_fail(f"Role mismatch. Expected SUPER_ADMIN, got: {role}")
            
        print_pass(f"Session affirmed as {role}")
        
    except Exception as e:
        if server_process:
            server_process.kill()
        print_fail(f"Role verification threw exception: {e}")

    # Cleanup
    if server_process:
        print_step("Terminating ephemeral server...")
        server_process.terminate()
        server_process.wait(timeout=5)
        print_pass("Ephemeral server terminated.")

    # 6. Print PASS
    print(f"\n{GREEN}=== DOCTOR VERIFICATION PASSED ==={RESET}\n")

if __name__ == '__main__':
    main()

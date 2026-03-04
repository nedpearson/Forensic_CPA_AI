import os
import sys
import time
import requests
import uuid
import subprocess
from dotenv import load_dotenv

if not os.path.exists('app.py'):
    print("Please run this script from the project root directory (Forensic_CPA_AI).")
    sys.exit(1)

load_dotenv()

PORT = 5005
BASE_URL = f"http://localhost:{PORT}"
TEST_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'nedpearson@gmail.com')
TEST_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', '1Pearson2')

def print_pass(msg):
    print(f"\033[92m[PASS]\033[0m {msg}")

def print_fail(msg):
    print(f"\033[91m[FAIL]\033[0m {msg}")

def start_server():
    print(f"Starting test server on port {PORT}...")
    env = os.environ.copy()
    env['FLASK_APP'] = 'app.py'
    env['FLASK_RUN_PORT'] = str(PORT)
    env['PORT'] = str(PORT)
    
    server_process = subprocess.Popen(
        [sys.executable, "-m", "flask", "run", "--port", str(PORT)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    for _ in range(20):
        try:
            time.sleep(1)
            response = requests.get(f"{BASE_URL}/")
            if response.status_code == 200:
                print_pass(f"Server is running on port {PORT}")
                return server_process
        except requests.ConnectionError:
            continue
            
    print_fail("Server failed to start within 20 seconds.")
    server_process.terminate()
    print(server_process.stderr.read().decode())
    return None

def main():
    print("=== VERIFYING DOCUMENT APPROVAL IDEMPOTENCY ===")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from database import init_db
        init_db()
    except Exception as e:
        print_fail(f"Failed to bootstrap database: {e}")
        return
        
    server = start_server()
    if not server:
        sys.exit(1)
        
    session = requests.Session()
    session.headers.update({'Content-Type': 'application/json'})

    try:
        print(f"\nLogging in as {TEST_EMAIL}...")
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        
        if login_resp.status_code != 200:
            print_fail(f"Login failed: {login_resp.text}")
            return
        print_pass("Logged in successfully.")
        
        dummy_csv = f"test_approve_{uuid.uuid4().hex[:8]}.csv"
        with open(dummy_csv, "w") as f:
            f.write(f"Date,Description,Amount\n2023-01-01,Approval Test {uuid.uuid4().hex[:8]},-100.00\n")
            
        print("\nUploading test CSV document...")
        session.headers.pop('Content-Type')
        with open(dummy_csv, "rb") as f:
            csv_resp = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'})
            
        if csv_resp.status_code != 200:
            print_fail(f"Upload preview failed: {csv_resp.text}")
            return
            
        preview_id = csv_resp.json().get('preview_id')
        print_pass(f"Preview generated (ID: {preview_id})")
        
        session.headers.update({'Content-Type': 'application/json'})
        commit_resp = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": preview_id})
        
        if commit_resp.status_code != 200:
            print_fail(f"Upload commit failed: {commit_resp.text}")
            server.terminate()
            print("\n--- SERVER LOGS ---")
            print(server.stderr.read().decode())
            return
            
        doc_id = commit_resp.json().get('document_id')
        print_pass(f"Document committed (ID: {doc_id})")
        
        docs_resp = session.get(f"{BASE_URL}/api/docs/{doc_id}")
        if docs_resp.status_code == 200:
            doc_info = docs_resp.json()
            status = doc_info.get('status')
            if status == 'pending_approval':
                print_pass(f"Verified initial status: {status}")
            else:
                print_fail(f"Expected pending_approval, got: {status}")
                return
        else:
            print_fail(f"Could not fetch document info: {docs_resp.text}")
            return
            
        print("\nApproving document the first time...")
        approve_resp1 = session.post(f"{BASE_URL}/api/documents/{doc_id}/approve")
        
        if approve_resp1.status_code == 200:
            data1 = approve_resp1.json()
            if data1.get('transactions_approved') == 1:
                print_pass(f"Approval successful: {data1.get('transactions_approved')} transactions activated.")
            else:
                print_fail(f"Expected 1 transaction activated, got: {data1.get('transactions_approved')}")
                return
        else:
            print_fail(f"Approval failed: {approve_resp1.text}")
            return
            
        print("\nApproving document the second time (Idempotency Check)...")
        approve_resp2 = session.post(f"{BASE_URL}/api/documents/{doc_id}/approve")
        
        if approve_resp2.status_code == 200:
            data2 = approve_resp2.json()
            if data2.get('transactions_approved') == 0:
                print_pass(f"Idempotent approval successful: {data2.get('transactions_approved')} duplicate transactions activated.")
            else:
                print_fail(f"Expected 0 dupes activated, got {data2.get('transactions_approved')}")
        else:
            print_fail(f"Second approval failed: {approve_resp2.text}")
            
        if os.path.exists(dummy_csv):
            os.remove(dummy_csv)

    finally:
        print("\nShutting down test server...")
        server.terminate()

if __name__ == "__main__":
    main()

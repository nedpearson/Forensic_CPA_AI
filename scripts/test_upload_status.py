import os
import sys
import time
import requests
import threading
import subprocess
from dotenv import load_dotenv

# Ensure we're running from the project root
if not os.path.exists('app.py'):
    print("Please run this script from the project root directory (Forensic_CPA_AI).")
    sys.exit(1)

load_dotenv()

PORT = 5002
BASE_URL = f"http://localhost:{PORT}"
TEST_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'nedpearson@gmail.com')
TEST_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', '1Pearson2')

def print_pass(msg):
    # Using [PASS] instead of checkmarks which can cause UnicodeEncodeError on some Windows terminals
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
    
    # Wait for server to boot
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
    print("=== VERIFYING DOCUMENT UPLOAD STATUS TRACKING ===")
    
    # 0. Bootstrap DB
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from database import init_db
        init_db()
    except Exception as e:
        print_fail(f"Failed to bootstrap database: {e}")
        return
        
    # 1. Start Server
    server = start_server()
    if not server:
        sys.exit(1)
        
    session = requests.Session()
    session.headers.update({'Content-Type': 'application/json'})

    try:
        # 2. Login
        print(f"\nLogging in as {TEST_EMAIL}...")
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        
        if login_resp.status_code != 200:
            print_fail(f"Login failed: {login_resp.text}")
            return
        
        print_pass("Logged in successfully.")
        
        # 3. Create a dummy CSV file (Sync Flow)
        import uuid
        dummy_csv = "test_statement.csv"
        uid_val = str(uuid.uuid4())
        with open(dummy_csv, "w") as f:
            f.write(f"Date,Description,Amount\n2023-01-01,Test Transaction {uid_val},-100.00\n")
            
        print("\nUploading test CSV document...")
        session.headers.pop('Content-Type')
        with open(dummy_csv, "rb") as f:
            csv_resp = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'})
            
        if csv_resp.status_code != 200:
            print_fail(f"Upload preview failed: {csv_resp.text}")
            return
            
        csv_data = csv_resp.json()
        preview_id = csv_data.get('preview_id')
        print_pass(f"Preview generated (ID: {preview_id})")
        
        session.headers.update({'Content-Type': 'application/json'})
        commit_resp = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": preview_id})
        
        if commit_resp.status_code != 200:
            print_fail(f"Upload commit failed: {commit_resp.text}")
            server.terminate()
            print("\n--- SERVER LOGS ---")
            print(server.stderr.read().decode())
            return
            
        commit_data = commit_resp.json()
        doc_id = commit_data.get('document_id')
        print_pass(f"Document committed (ID: {doc_id})")
        
        # 3.5 Approve the document
        approve_resp = session.post(f"{BASE_URL}/api/documents/{doc_id}/approve")
        if approve_resp.status_code != 200:
            print_fail(f"Could not approve document: {approve_resp.text}")
            return
        print_pass(f"Document explicitly approved.")
        
        # 4. Verify Document Status
        docs_resp = session.get(f"{BASE_URL}/api/docs/{doc_id}")
        if docs_resp.status_code == 200:
            doc_info = docs_resp.json()
            status = doc_info.get('status')
            parsed = doc_info.get('parsed_transaction_count')
            imported = doc_info.get('import_transaction_count')
            
            if status == 'approved' and imported == 1:
                print_pass(f"Verified Document Status: {status} (Parsed: {parsed}, Imported: {imported})")
            else:
                print_fail(f"Expected approved status with 1 import, got Status: {status}, Extracted: {parsed}, Imported: {imported}")
        else:
            print_fail(f"Could not fetch document info: {docs_resp.text}")
            
        # 5. Test Deduplication
        print("\nUploading test CSV document again (Deduplication)...")
        session.headers.pop('Content-Type')
        with open(dummy_csv, "rb") as f:
            dup_resp = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'})
            
        if dup_resp.status_code == 200 and dup_resp.json().get('mode') == 'duplicate':
            print_pass("Deduplication detected correctly.")
        else:
            print_fail(f"Expected deduplication detection, got: {dup_resp.text}")

        if os.path.exists(dummy_csv):
            os.remove(dummy_csv)

    finally:
        print("\nShutting down test server...")
        server.terminate()

if __name__ == "__main__":
    main()

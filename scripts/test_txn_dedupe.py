import os
import sys
import time
import requests
import subprocess
import sqlite3
from dotenv import load_dotenv

if not os.path.exists('app.py'):
    print("Please run this script from the project root directory (Forensic_CPA_AI).")
    sys.exit(1)

load_dotenv()

PORT = 5003
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
    print("=== VERIFYING TRANSACTION DEDUPLICATION ===")
    
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
        login_resp = session.post(f"{BASE_URL}/api/auth/login", json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD
        })
        
        if login_resp.status_code != 200:
            print_fail(f"Login failed: {login_resp.text}")
            return
        
        print_pass("Logged in successfully.")
        
        # Doc 1 -> 1 transaction
        import uuid
        uid_val = str(uuid.uuid4())
        txn_desc = f"Dedupe Target {uid_val}"

        csv1 = "test_txn_dedupe_1.csv"
        with open(csv1, "w") as f:
            f.write(f"Date,Description,Amount\n2023-01-01,{txn_desc},-100.00\n")
            
        print("\nUploading first document...")
        session.headers.pop('Content-Type')
        with open(csv1, "rb") as f:
            resp1 = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'})
            
        if resp1.status_code != 200:
            print_fail(f"Upload 1 preview failed: {resp1.text}")
            return
            
        prev_id1 = resp1.json().get('preview_id')
        session.headers.update({'Content-Type': 'application/json'})
        commit1 = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": prev_id1})
        if commit1.status_code != 200:
            print_fail(f"Upload 1 commit failed: {commit1.text}")
            return
            
        print_pass("First document imported.")

        # Query DB to count
        from database import DB_PATH
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as cnt FROM transactions WHERE description = ?", (txn_desc,))
        initial_count = c.fetchone()['cnt']
        print_pass(f"Initial DB count for '{txn_desc}' = {initial_count}")

        # Doc 2 -> same transaction + extra to alter document hash
        csv2 = "test_txn_dedupe_2.csv"
        with open(csv2, "w") as f:
            f.write(f"Date,Description,Amount\n2023-01-01,{txn_desc},-100.00\n2023-01-02,Different {uid_val},-50.00\n")
            
        print("\nUploading second document (cross-document dupe logic)...")
        session.headers.pop('Content-Type')
        with open(csv2, "rb") as f:
            resp2 = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'})
            
        if resp2.status_code != 200:
            print_fail(f"Upload 2 preview failed: {resp2.text}")
            return
            
        prev_id2 = resp2.json().get('preview_id')
        session.headers.update({'Content-Type': 'application/json'})
        commit2 = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": prev_id2})
        if commit2.status_code != 200:
            print_fail(f"Upload 2 commit failed: {commit2.text}")
            return

        c.execute("SELECT COUNT(*) as cnt FROM transactions WHERE description = ?", (txn_desc,))
        final_count = c.fetchone()['cnt']
        
        if final_count == 1:
            print_pass(f"FINAL DB COUNT for '{txn_desc}': {final_count} (Idempotency SUCCESS)")
            c.execute("SELECT id, trans_date, description, amount, txn_fingerprint FROM transactions WHERE description = ?", (txn_desc,))
            row = c.fetchone()
            print_pass(f"DB QUERY PROOF: ID: {row['id']}, Hash: {row['txn_fingerprint']}")
        else:
            print_fail(f"FINAL DB COUNT: {final_count} (Expected 1)")

        if os.path.exists(csv1): os.remove(csv1)
        if os.path.exists(csv2): os.remove(csv2)

    finally:
        print("\nShutting down test server...")
        server.terminate()

if __name__ == "__main__":
    main()

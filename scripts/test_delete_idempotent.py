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

PORT = 5006
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
    print("=== VERIFYING DOCUMENT DELETION AND ORPHAN CLEANUP ===")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from database import init_db, get_db
        init_db()
    except Exception as e:
        print_fail(f"Failed to bootstrap database: {e}")
        return
        
    server = start_server()
    if not server:
        sys.exit(1)
        
    session = requests.Session()
    session.headers.update({'Content-Type': 'application/json'})
    
    dummy_csv_1 = None
    dummy_csv_2 = None

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
        
        # 1. Create unique transaction content
        uid_val = str(uuid.uuid4())[:8]
        dummy_csv_1 = f"test_delete_{uid_val}_1.csv"
        with open(dummy_csv_1, "w") as f:
            f.write(f"Date,Description,Amount\n2023-01-01,Delete Test {uid_val},-100.00\n")
            
        dummy_csv_2 = f"test_delete_{uid_val}_2.csv"
        with open(dummy_csv_2, "w") as f:
            f.write(f"Date,Description,Amount\n2023-01-01,Delete Test {uid_val},-100.00\n# this makes the file sha256 different\n")

        # Upload Doc 1
        print("\nUploading Doc 1...")
        session.headers.pop('Content-Type')
        with open(dummy_csv_1, "rb") as f:
            csv_resp_1 = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'})
        preview_id_1 = csv_resp_1.json().get('preview_id')
        session.headers.update({'Content-Type': 'application/json'})
        commit_resp_1 = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": preview_id_1})
        doc_id_1 = commit_resp_1.json().get('document_id')
        print_pass(f"Doc 1 committed (ID: {doc_id_1})")
        
        approve_resp1 = session.post(f"{BASE_URL}/api/documents/{doc_id_1}/approve")
        
        # Upload Doc 2 (Duplicate transactions)
        print("\nUploading Doc 2 (Duplicate)...")
        session.headers.pop('Content-Type')
        with open(dummy_csv_2, "rb") as f:
            csv_resp_2 = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'})
        preview_id_2 = csv_resp_2.json().get('preview_id')
        session.headers.update({'Content-Type': 'application/json'})
        commit_resp_2 = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": preview_id_2})
        doc_id_2 = commit_resp_2.json().get('document_id')
        print_pass(f"Doc 2 committed (ID: {doc_id_2})")
        
        # Check source counts via DB directly just for QA verification
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM transactions WHERE description = ?", (f"Delete Test {uid_val}",))
        txns = cursor.fetchall()
        
        if len(txns) == 1:
            print_pass(f"Deduplication preserved 1 unique transaction row.")
            txn_id = txns[0]['id']
        else:
            print_fail(f"Expected 1 duplicate transaction, found {len(txns)}")
            return
            
        cursor.execute("SELECT COUNT(*) as c FROM transaction_sources WHERE transaction_id = ?", (txn_id,))
        source_count = cursor.fetchone()['c']
        
        if source_count == 2:
            print_pass(f"Transaction correctly linked to 2 sources (Docs {doc_id_1}, {doc_id_2}).")
        else:
            print_fail(f"Expected 2 transaction sources, found {source_count}")
            return
            
        # Delete Doc 2
        print(f"\nDeleting Doc 2 ({doc_id_2})...")
        del_resp_2 = session.delete(f"{BASE_URL}/api/documents/{doc_id_2}")
        if del_resp_2.status_code == 200:
            print_pass("Doc 2 deleted successfully.")
        else:
            print_fail(f"Doc 2 deletion failed: {del_resp_2.text}")
            return
            
        # Verify transaction still exists because Doc 1 still links to it
        cursor.execute("SELECT COUNT(*) as c FROM transactions WHERE id = ?", (txn_id,))
        txn_exists = cursor.fetchone()['c']
        if txn_exists == 1:
            print_pass("Transaction preserved correctly (Doc 1 still references it).")
        else:
            print_fail("Transaction was improperly deleted while sources remained!")
            return
            
        # Delete Doc 1
        print(f"\nDeleting Doc 1 ({doc_id_1})...")
        del_resp_1 = session.delete(f"{BASE_URL}/api/documents/{doc_id_1}")
        if del_resp_1.status_code == 200:
            print_pass("Doc 1 deleted successfully.")
            
        # Verify transaction is now an orphan and was removed
        cursor.execute("SELECT COUNT(*) as c FROM transactions WHERE id = ?", (txn_id,))
        txn_orphan = cursor.fetchone()['c']
        if txn_orphan == 0:
            print_pass("Orphan transaction cleanly truncated and deleted.")
        else:
            print_fail("Transaction was NOT deleted even though all sources were removed!")
            return
            
        conn.close()

    finally:
        print("\nShutting down test server...")
        server.terminate()
        if dummy_csv_1 and os.path.exists(dummy_csv_1):
            os.remove(dummy_csv_1)
        if dummy_csv_2 and os.path.exists(dummy_csv_2):
            os.remove(dummy_csv_2)

if __name__ == "__main__":
    main()

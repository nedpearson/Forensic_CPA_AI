import os
import sys
import time
import requests
import uuid
import subprocess
from dotenv import load_dotenv

if not os.path.exists('app.py'):
    print("Please run this script from the project root directory.")
    sys.exit(1)

load_dotenv()

PORT = 5008
BASE_URL = f"http://localhost:{PORT}"
TEST_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'nedpearson@gmail.com')
TEST_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', '1Pearson2')

def print_pass(msg):
    print(f"\033[92m[PASS]\033[0m {msg}")

def print_fail(msg):
    print(f"\033[91m[FAIL]\033[0m {msg}")

def start_server():
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
            
    print_fail("Server failed to start.")
    server_process.terminate()
    return None

def main():
    print("=== SMOKE TEST: DEDUPLICATION AND ORPHAN CLEANUP ===")
    
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
    session.post(f"{BASE_URL}/api/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    
    uid_val = str(uuid.uuid4())[:8]
    dummy_csv_1 = f"test_smoke_{uid_val}_1.csv"
    dummy_csv_2 = f"test_smoke_{uid_val}_2.csv"
    
    # Write initial document with 1 transaction
    with open(dummy_csv_1, "w") as f:
        f.write(f"Date,Description,Amount\n2023-01-01,Shared Txn {uid_val},-100.00\n")
        
    # Write second document containing the SAME overlapping transaction PLUS a new one
    with open(dummy_csv_2, "w") as f:
        f.write(f"Date,Description,Amount\n2023-01-01,Shared Txn {uid_val},-100.00\n2023-01-02,Unique Txn {uid_val},-50.00\n")

    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # 1. Upload Document 1
        with open(dummy_csv_1, "rb") as f:
            prev1 = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'}).json()
        doc_resp_1 = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": prev1['preview_id']}).json()
        doc_id_1 = doc_resp_1.get('document_id')
        print_pass(f"Doc 1 uploaded (ID: {doc_id_1})")
        
        # 1a. Upload EXACT same document twice
        with open(dummy_csv_1, "rb") as f:
            prev_dup = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'}).json()
            
        if 'error' in prev_dup:
            print_pass(f"Upload same file twice: doc count remains 1 (aborted at preview: {prev_dup['error']}).")
        else:
            doc_dup = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": prev_dup.get('preview_id', '')}).json()
            if not doc_dup.get('document_id') or doc_dup.get('document_id') == doc_id_1:
                print_pass("Upload same file twice: doc count remains 1 (deduped correctly).")
            else:
                print_fail("Duplicate document was created incorrectly!")
                return
                
        # 2. Approve Doc 1 (Import transactions)
        app_resp_1 = session.post(f"{BASE_URL}/api/documents/{doc_id_1}/approve").json()
        imported_count = app_resp_1.get('transactions_approved', 0)
        print_pass(f"Import Run 1: {imported_count} transactions imported.")
        
        # 2a. Approve Doc 1 AGAIN (Import twice)
        app_resp_dup = session.post(f"{BASE_URL}/api/documents/{doc_id_1}/approve").json()
        dup_count = app_resp_dup.get('transactions_approved', 0)
        if dup_count == 0:
            print_pass("Import twice: txn count unchanged on second run (0 added).")
        else:
            print_fail(f"Import twice failed: added {dup_count} transactions!")
            return
            
        # 3. Upload Document 2 (Overlapping transaction)
        with open(dummy_csv_2, "rb") as f:
            prev2 = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'}).json()
        doc_resp_2 = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": prev2['preview_id']}).json()
        doc_id_2 = doc_resp_2.get('document_id')
        print_pass(f"Doc 2 uploaded with overlap (ID: {doc_id_2})")
        
        session.post(f"{BASE_URL}/api/documents/{doc_id_2}/approve").json()
        
        # Verify transaction counts in DB
        cursor.execute("SELECT id FROM transactions WHERE description = ?", (f"Shared Txn {uid_val}",))
        shared_txns = cursor.fetchall()
        if len(shared_txns) == 1:
            print_pass("Overlapping txn count did NOT increase (deduped perfectly).")
            shared_txn_id = shared_txns[0]['id']
        else:
            print_fail(f"Overlapping transaction duplicated! Found {len(shared_txns)}.")
            return
            
        cursor.execute("SELECT COUNT(*) as c FROM transaction_sources WHERE transaction_id = ?", (shared_txn_id,))
        src_count = cursor.fetchone()['c']
        if src_count == 2:
            print_pass(f"transaction_sources shows 2 sources for the overlapping txn.")
        else:
            print_fail(f"Expected 2 sources, found {src_count}.")
            return
            
        # 4. Delete Doc 2
        del_resp = session.delete(f"{BASE_URL}/api/documents/{doc_id_2}")
        if del_resp.status_code == 200:
            print_pass("Doc 2 deleted successfully.")
            
        # Verify decrements 
        cursor.execute("SELECT COUNT(*) as c FROM transaction_sources WHERE transaction_id = ?", (shared_txn_id,))
        src_count_after = cursor.fetchone()['c']
        if src_count_after == 1:
            print_pass("Delete one doc: transaction_sources decremented perfectly (now 1).")
        else:
            print_fail(f"Source count decrement failed, found {src_count_after}.")
            return
            
        cursor.execute("SELECT COUNT(*) as c FROM transactions WHERE id = ?", (shared_txn_id,))
        txn_remaining = cursor.fetchone()['c']
        if txn_remaining == 1:
            print_pass("Delete one doc: shared txn remains perfectly because it's sourced by Doc 1.")
        else:
            print_fail("Shared transaction was incorrectly deleted!")
            return
            
        # Clean up Doc 1 to prevent DB leaking
        session.delete(f"{BASE_URL}/api/documents/{doc_id_1}")
        
    finally:
        server.terminate()
        conn.close()
        for f in [dummy_csv_1, dummy_csv_2]:
            if os.path.exists(f):
                os.remove(f)
                
    print("\n=== SMOKE TEST SUCCEEDED ===")

if __name__ == "__main__":
    main()

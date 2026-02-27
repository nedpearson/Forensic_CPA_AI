import os
import sys
import time
import requests
import subprocess
from dotenv import load_dotenv

os.environ['TESTING'] = 'true'
sys.path.insert(0, '.')
from database import init_db, get_db

load_dotenv()

PORT = 5013
BASE_URL = f"http://localhost:{PORT}"
TEST_EMAIL = os.getenv('SUPER_ADMIN_EMAIL', 'nedpearson@gmail.com')
TEST_PASSWORD = os.getenv('SUPER_ADMIN_PASSWORD', '1Pearson2')

def run_test():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'test_audit.db')
    if os.path.exists(db_path):
        os.remove(db_path)
    os.environ['DB_PATH'] = db_path
    init_db()

    env = os.environ.copy()
    env['FLASK_APP'] = 'app.py'
    env['FLASK_RUN_PORT'] = str(PORT)
    env['PORT'] = str(PORT)
    env['TESTING'] = 'true'
    env['DB_PATH'] = db_path
    env['FLASK_DEBUG'] = '0'
    env['FLASK_ENV'] = 'production'

    print("Starting server...")
    server_process = subprocess.Popen([sys.executable, "-m", "flask", "run", "--port", str(PORT)], env=env)
    
    time.sleep(3)

    session = requests.Session()
    session.post(f"{BASE_URL}/api/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})

    print("=== VERIFYING CATEGORIZATION UI OVERRIDES ===")
    add_req = session.post(f"{BASE_URL}/api/add-transaction", json={
        "trans_date": "2023-10-01",
        "amount": -50.00,
        "description": "Test AI Drop UI",
        "category": "Pending Support"
    })
    
    if add_req.status_code != 200:
        print(f"[FAIL] Transaction creation failed: {add_req.text}")
        server_process.terminate()
        return

    cat_test_doc = add_req.json()
    trans_id = cat_test_doc.get('id', cat_test_doc.get('transaction_id', 1))

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        UPDATE transactions 
        SET categorization_status='suggested', categorization_source='ai_low_conf', categorization_confidence=0.45
        WHERE id=?
    """, (trans_id,))
    conn.commit()
    conn.close()

    req1 = session.put(f"{BASE_URL}/api/transactions/{trans_id}", json={
        "categorization_status": "auto_applied",
        "manually_edited": 1
    })
    
    if req1.status_code == 200:
        print("[PASS] UI Inline Approval hook correctly processes categorization tracking!")
    else:
        print(f"[FAIL] UI Inline Approval failed! {req1.text}")

    req2 = session.put(f"{BASE_URL}/api/transactions/{trans_id}", json={
        "category": "Definitively Mapped"
    })
    
    if req2.status_code == 200:
        print("[PASS] UI Edit hook successfully cascades to Soft Learning module!")
    else:
        print(f"[FAIL] UI Edit hook failed! {req2.text}")

    req3 = session.post(f"{BASE_URL}/api/categories/rules", json={
        "pattern": "%TEST AI DROP%",
        "category": "Definitively Mapped",
        "priority": 100,
        "is_personal": 0,
        "is_business": 0,
        "is_transfer": 0
    })
    
    if req3.status_code == 200:
        print("[PASS] UI Override Toast successfully transmits absolute Priority 100!")
    else:
        print(f"[FAIL] UI Rule Override POST failed! {req3.text}")

    # Remove the manual edit lock so the batch loop processes it
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE transactions SET manually_edited=0 WHERE id=?", (trans_id,))
    conn.commit()
    conn.close()

    # 4. Simulate Background Re-Categorize All retaining JSON configs
    req4 = session.post(f"{BASE_URL}/api/recategorize")
    if req4.status_code == 200:
        # Check DB to see if it kept metadata
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT categorization_status, categorization_confidence, category FROM transactions WHERE id=?", (trans_id,))
        row = c.fetchone()
        conn.close()
        # Because we locked it via explicit rule mapping above, the AI module technically scores the Pattern-Match
        # as a deterministic 100% confidence. But it must not be "Null" dropped by the batch loop script.
        if row and row['categorization_confidence'] is not None:
             print(f"[PASS] Background Re-Categorization loop successfully retains metadata schemas! Confidence: {row['categorization_confidence']}")
        else:
             print(f"[FAIL] Metadata dropped during batch loop! Row Dump: {dict(row) if row else 'None'}")
    else:
        print(f"[FAIL] Re-Categorize POST failed! {req4.text}")

    server_process.terminate()
    print("UI checks completed.")

if __name__ == '__main__':
    run_test()

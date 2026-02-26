import os
import sys
import time
import requests
import subprocess
from playwright.sync_api import sync_playwright
from dotenv import load_dotenv

if not os.path.exists('app.py'):
    print("Please run this script from the project root directory.")
    sys.exit(1)

load_dotenv()

PORT = 5007
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
    print("=== VERIFYING UI ACTIONS (Approve/Delete) ===")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from database import init_db
        init_db()
    except Exception as e:
        print_fail(f"Failed to bootstrap DB: {e}")
        return
        
    server = start_server()
    if not server:
        sys.exit(1)
        
    # Pre-seed a test document via API
    session = requests.Session()
    session.post(f"{BASE_URL}/api/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    
    import uuid
    uid_val = str(uuid.uuid4())[:8]
    dummy_csv = f"test_ui_doc_{uid_val}.csv"
    with open(dummy_csv, "w") as f:
        f.write(f"Date,Description,Amount\n2023-01-01,Test Entry {uid_val},-50.00\n")
        
    with open(dummy_csv, "rb") as f:
        preview = session.post(f"{BASE_URL}/api/upload/preview", files={"file": f}, data={'doc_category': 'test'}).json()
        
    commit = session.post(f"{BASE_URL}/api/upload/commit", json={"preview_id": preview['preview_id']}).json()
    doc_id = commit['document_id']
    
    print_pass(f"Seeded document (ID: {doc_id}) with pending_approval status.")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        # Login
        page.goto(BASE_URL)
        page.fill('#email', TEST_EMAIL)
        page.fill('#password', TEST_PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_timeout(2000)
        
        # Navigate to documents
        page.wait_for_selector('[data-page="documents"]')
        page.click('[data-page="documents"]')
        page.wait_for_selector('#documents-tbody tr')
        
        # Check actions column
        row = page.locator(f"tr:has-text('{dummy_csv}')")
        
        # Verify Approve button exists 
        approve_btn = row.locator("button:has-text('Approve')")
        if approve_btn.is_visible():
            print_pass("Approve button is visibly rendered on pending_approval doc.")
        else:
            print_fail("Approve button missing!")
            
        # Verify Delete button exists
        delete_btn = row.locator("button[title='Delete Document & Truncate Orphan Data']")
        if delete_btn.is_visible():
            print_pass("Delete button is visibly rendered.")
        else:
            print_fail("Delete button missing!")
            
        # Verify Dialog Modal String
        dialog_text = None
        def handle_dialog(dialog):
            nonlocal dialog_text
            dialog_text = dialog.message
            dialog.dismiss()
            
        page.on("dialog", handle_dialog)
        
        delete_btn.click()
        page.wait_for_timeout(500) # wait for event sequence
        
        expected_msg = "Deleting this document will remove the document and any transactions/data imported from it."
        if dialog_text == expected_msg:
            print_pass(f"Delete confirmation modal text matches strictly: '{dialog_text}'")
        else:
            print_fail(f"Modal text mismatch. Expected: '{expected_msg}', Got: '{dialog_text}'")
            
        # Clear document normally
        session.delete(f"{BASE_URL}/api/documents/{doc_id}")
        
        browser.close()
        
    os.remove(dummy_csv)
    server.terminate()
    print("UI checks completed.")

if __name__ == "__main__":
    main()

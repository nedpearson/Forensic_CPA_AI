import os
import sys

# Change to project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

app.config['TESTING'] = True

def run_tests():
    print("=== TESTING .QBW PIPELINE ===")
    
    # 1. Test Valid QBW
    import time
    valid_qbw = (b"0" * 2048) + str(time.time()).encode()  # larger than 1024 bytes and unique
    with open("test_valid.qbw", "wb") as f:
        f.write(valid_qbw)
        
    auth_token = os.getenv("UPLOAD_AUTH_TOKEN", "test_token")
    os.environ["UPLOAD_AUTH_TOKEN"] = auth_token
    
    client = app.test_client()
    
    with app.app_context():
        from database import get_db
        db = get_db()
        user = db.execute("SELECT id FROM users LIMIT 1").fetchone()
        if not user:
            from database import create_demo_user
            create_demo_user()
            user = db.execute("SELECT id FROM users LIMIT 1").fetchone()
            
        test_user_id = user['id']
        # The UPLOAD_AUTH_TOKEN hardcodes id=1 in app.py's load_user_from_request.
        # This is what's failing if id=1 is missing.
        # Let's bypass UPLOAD_AUTH_TOKEN and just use flask_login properly:
        pass
    
    # Drop the headers and manual token. Use login via standard POST.
    with client:
        # We need a proper user session
        app.config['LOGIN_DISABLED'] = False
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_user_id)
            sess['_fresh'] = True
            
        with open("test_valid.qbw", "rb") as f:
            res = client.post('/api/upload/preview', data={
                'file': (f, 'test_valid.qbw'),
                'doc_type': 'auto',
                'doc_category': 'test'
            })
            
            data = res.get_json()
        assert res.status_code == 200, f"Expected 200 for valid QBW, got {res.status_code}: {data}"
        assert data['status'] == 'ok'
        assert data['mode'] == 'async_zip'
        assert "QuickBooks file staged" in data['message']
        print("[PASS] Valid >1KB .qbw upload is safely staged.")
        
        import time
        time.sleep(2)  # Wait for background thread
        
        with app.app_context():
            doc = db.execute("SELECT status, failure_reason FROM documents WHERE id = ?", (data['document_id'],)).fetchone()
            assert doc['status'] == 'failed', f"Expected failed, got {doc['status']}"
            assert "Needs Conversion" in doc['failure_reason'], "Expected explicit failure reason"
            print("[PASS] QBW successfully routed to an explicit actionable failed state.")

        # Test duplicate QBW: uploading it again
        # The file hash is identical, so it should be rejected
    with open("test_valid.qbw", "rb") as f:
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_user_id)
        res2 = client.post('/api/upload/preview', data={
            'file': (f, 'test_valid.qbw'),
            'doc_type': 'auto',
            'doc_category': 'test'
        })
        data2 = res2.get_json()
        assert res2.status_code == 200
        assert data2['mode'] == 'duplicate'
        assert "has already been uploaded" in data2['message']
        print("[PASS] Duplicate prevention correctly caught duplicate .qbw file.")
        
    # 2. Test Invalid/Corrupt QBW (< 1KB)
    invalid_qbw = b"tiny_corrupt_file"
    with open("test_invalid.qbw", "wb") as f:
        f.write(invalid_qbw)
        
    with open("test_invalid.qbw", "rb") as f:
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_user_id)
        res3 = client.post('/api/upload/preview', data={
            'file': (f, 'test_invalid.qbw'),
            'doc_type': 'auto',
            'doc_category': 'test'
        })
        assert res3.status_code == 400
        data3 = res3.get_json()
        assert "Failed to parse document: File appears invalid" in data3['error']
        print("[PASS] Invalid <1KB .qbw upload is safely rejected.")
        
    # 3. Test Existing Normal Upload (CSV)
    valid_csv = b"Date,Description,Amount\n2025-01-01,Test,10.0\n"
    with open("test_legacy.csv", "wb") as f:
        f.write(valid_csv)
    with open("test_legacy.csv", "rb") as f:
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_user_id)
        res4 = client.post('/api/upload/preview', data={
            'file': (f, 'test_legacy.csv'),
            'doc_type': 'auto',
            'doc_category': 'test'
        })
        assert res4.status_code == 200, f"Expected 200 for normal CSV, got {res4.status_code}: {res4.get_json()}"
        data4 = res4.get_json()
        assert data4['mode'] == 'preview'
        assert len(data4['transactions']) == 1
        print("[PASS] Traditional file uploads (.csv) remain completely unaffected.")
        
    os.remove("test_valid.qbw")
    os.remove("test_invalid.qbw")
    os.remove("test_legacy.csv")
    print("=== ALL TESTS PASSED ===")
    
if __name__ == "__main__":
    run_tests()

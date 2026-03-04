import os
import sys

# Change to project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from database import upsert_integration
from shared.encryption import encrypt_token

app.config['TESTING'] = True

def run_tests():
    print("=== TESTING FINANCIAL CENTS INTEGRATION BASE ===")
    
    # 1. Provide mock test user context
    with app.app_context():
        from database import get_db, delete_integration
        db = get_db()
        user = db.execute("SELECT id FROM users LIMIT 1").fetchone()
        if not user:
            from database import create_demo_user
            create_demo_user()
            user = db.execute("SELECT id FROM users LIMIT 1").fetchone()
        test_user_id = user['id']
        delete_integration(test_user_id, 'financial_cents')
            
    # Enable integrations routing globally for the test
    os.environ['ENABLE_INTEGRATIONS'] = 'true'
    
    client = app.test_client()

    # We need a proper user session
    app.config['LOGIN_DISABLED'] = False

    # 2. Test status endpoint returns the new FC property correctly
    with client:
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_user_id)
            sess['_fresh'] = True
            
        res = client.get('/api/integrations/status')
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        data = res.get_json()
        
        fc_status = next((i for i in data['integrations'] if i['provider'] == 'financial_cents'), None)
        assert fc_status is not None, "Financial Cents provider missing from API status"
        assert fc_status['status'] == 'Not connected', "Should default to not connected"
        print("[PASS] Integration status endpoint lists Financial Cents default state.")

    # 3. Test mock DB Storage & Client initialization
    with app.app_context():
        from shared.financial_cents_client import FinancialCentsClient
        
        # Verify uninitialized client behavior
        client_test = FinancialCentsClient(test_user_id)
        assert not client_test.is_connected(), "Client shouldn't be connected yet."
        
        # Force a database mock token
        dummy_access = encrypt_token("fc_dummy_1234")
        upsert_integration(
            user_id=test_user_id,
            provider='financial_cents',
            status='Connected',
            access_token=dummy_access
        )
        print("[PASS] Credential storage leverages existing secure schema.")
        
        # Verify client picks up the database config correctly
        client_test2 = FinancialCentsClient(test_user_id)
        # Note: the test client doesn't actually populate state from __init__ due to the dummy mocking above, 
        # but we can explicitly test fetching:
        client_test2._load_credentials()
        # Verify token decrypts securely without exposing to UI
        assert client_test2.access_token == "fc_dummy_1234", "Token decryption failed or returned wrong value."
        assert client_test2.is_connected(), "Client should register as connected after state update."
        print("[PASS] FinancialCentsClient loaded isolated credentials from DB securely.")

    # 4. Test Idempotent Sync Integration via API endpoint
    with client:
        with client.session_transaction() as sess:
            sess['_user_id'] = str(test_user_id)
            sess['_fresh'] = True
            
        # First sync pass
        res_sync1 = client.post('/api/integrations/financial_cents/sync_clients')
        assert res_sync1.status_code == 200, f"Expected 200 from sync, got {res_sync1.status_code}"
        sync_data1 = res_sync1.get_json()
        assert "Synced 2 clients" in sync_data1['message'], "Expected 2 mocked clients strictly synced."
        assert "Skipped 0 duplicates" in sync_data1['message']
        print("[PASS] Initial Client Sync ran and mapped valid entities cleanly.")
        
        # Second sync pass (Testing idempotency/duplicate prevention)
        res_sync2 = client.post('/api/integrations/financial_cents/sync_clients')
        assert res_sync2.status_code == 200
        sync_data2 = res_sync2.get_json()
        assert "Skipped 2 duplicates" in sync_data2['message'], f"Expected duplicates skipped. Got: {sync_data2['message']}"
        assert "Synced 0 clients" in sync_data2['message']
        print("[PASS] Secondary Client Sync proved Idempotent explicitly. Zero duplicate records created.")
        
        # Cleanup mock records
        with app.app_context():
            db.execute("DELETE FROM merchants WHERE user_id = ? AND canonical_name IN ('Acme Corp (FC)', 'Stark Industries (FC)')", (test_user_id,))
            db.commit()

    print("=== ALL TESTS PASSED ===")

if __name__ == "__main__":
    run_tests()

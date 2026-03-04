import pytest
from app import app
from database import get_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        setup_mock_data()
        client.post('/api/auth/login', json={'email': 'mock@test.com', 'password': 'password'})
        client.post('/api/business/switch', json={'company_id': 1})
        yield client

def setup_mock_data():
    from database import init_db
    import werkzeug.security
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    # Ensure user and company exist
    hashed = werkzeug.security.generate_password_hash("password")
    cursor.execute("INSERT OR IGNORE INTO users (id, email, password_hash) VALUES (1, 'mock@test.com', ?)", (hashed,))
    cursor.execute("INSERT OR IGNORE INTO companies (id, name, owner_user_id) VALUES (1, 'Mock Company', 1)")
    cursor.execute("INSERT OR IGNORE INTO company_memberships (company_id, user_id, role) VALUES (1, 1, 'owner')")
    
    # Insert some dummy transactions for company_id = 1
    cursor.execute("DELETE FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE user_id = 1)")
    cursor.execute("INSERT OR IGNORE INTO accounts (id, user_id, account_name, account_type) VALUES (1, 1, 'Mock', 'checking')")
    cursor.execute("INSERT INTO transactions (account_id, user_id, company_id, trans_date, description, amount, category, is_personal, is_flagged, trans_type) VALUES (1, 1, 1, '2023-01-01', 'Uber Eats', -50.0, 'Meals', 1, 0, 'debit')")
    cursor.execute("INSERT INTO transactions (account_id, user_id, company_id, trans_date, description, amount, category, is_personal, is_flagged, trans_type) VALUES (1, 1, 1, '2023-01-02', 'Suspicious Vendor', -5000.0, 'Contractors', 0, 1, 'debit')")
    cursor.execute("INSERT INTO transactions (account_id, user_id, company_id, trans_date, description, amount, category, is_personal, is_flagged, trans_type) VALUES (1, 1, 1, '2023-01-03', 'Big Client Deposit', 10000.0, 'Deposit', 0, 0, 'credit')")
    conn.commit()
    conn.close()

def test_scenario_reclassification(client):
    res = client.post('/api/simulator/run', json={
        "scenario_type": "reclassification",
        "parameters": {
            "target_category": "Meals",
            "vendor_match": "Uber"
        }
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert data['scenario'] == 'Reclassification'
    assert data['delta'] == 50.0 # Reclassed an expense, so delta is positive
    assert len(data['evidence_links']) == 1

def test_scenario_timing(client):
    res = client.post('/api/simulator/run', json={
        "scenario_type": "timing",
        "parameters": {
            "deferral_percentage": 50,
            "threshold": 5000
        }
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert data['scenario'] == 'Timing'
    assert data['delta'] == -5000.0 # Deferred 50% of 10k
    assert len(data['evidence_links']) == 1

def test_scenario_add_back(client):
    res = client.post('/api/simulator/run', json={
        "scenario_type": "add_back",
        "parameters": {}
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert data['delta'] == 50.0 # The one is_personal=1 tx
    assert len(data['evidence_links']) == 1

def test_scenario_controls_remediation(client):
    res = client.post('/api/simulator/run', json={
        "scenario_type": "controls_remediation",
        "parameters": {}
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert data['delta'] == 5000.0 # The one is_flagged=1 tx
    assert len(data['evidence_links']) == 1

def test_scenario_capitalization(client):
    res = client.post('/api/simulator/run', json={
        'scenario_type': 'capitalization',
        'parameters': {}
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert data['delta'] == 5000.0 # capitalizes the 5k expense -> removed from P&L -> NI goes up 5k Wait... 5k was flagged as missing or something?


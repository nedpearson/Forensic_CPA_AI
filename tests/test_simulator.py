import pytest
from app import app
from database import get_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        # Mock session for multi-tenancy auth
        with client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['active_company_id'] = 1 
            sess['company_role'] = 'owner'
        yield client

def setup_mock_data():
    conn = get_db()
    cursor = conn.cursor()
    # Insert some dummy transactions for company_id = 1
    cursor.execute("DELETE FROM transactions WHERE company_id = 1")
    cursor.execute("INSERT INTO transactions (company_id, user_id, trans_date, description, amount, category, is_personal, is_flagged) VALUES (1, 1, '2023-01-01', 'Uber Eats', -50.0, 'Meals', 1, 0)")
    cursor.execute("INSERT INTO transactions (company_id, user_id, trans_date, description, amount, category, is_personal, is_flagged) VALUES (1, 1, '2023-01-02', 'Suspicious Vendor', -5000.0, 'Contractors', 0, 1)")
    cursor.execute("INSERT INTO transactions (company_id, user_id, trans_date, description, amount, category, is_personal, is_flagged) VALUES (1, 1, '2023-01-03', 'Big Client Deposit', 10000.0, 'Revenue', 0, 0)")
    conn.commit()
    conn.close()

def test_scenario_reclassification(client):
    setup_mock_data()
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


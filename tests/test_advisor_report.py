import pytest
from app import app
from database import get_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        from database import init_db
        import werkzeug.security
        init_db()
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO users (id, email, password_hash) VALUES (999, 'mock999@test.com', ?)", (werkzeug.security.generate_password_hash("password"),))
        conn.execute("INSERT OR REPLACE INTO companies (id, name, owner_user_id) VALUES (999, 'Mock Company', 999)")
        conn.execute("INSERT OR REPLACE INTO company_memberships (company_id, user_id, role) VALUES (999, 999, 'owner')")
        conn.commit()
        
        client.post('/api/auth/login', json={'email': 'mock999@test.com', 'password': 'password'})
        client.post('/api/business/switch', json={'company_id': 999})
        yield client

def setup_mock_data():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO advisor_findings 
        (company_id, finding_id, analysis_run_id, category, severity, confidence, title, plain_english_explanation, forensic_rationale) 
        VALUES 
        (999, 'finding-101', 'RUN-999', 'category-A', 'danger', 95, 'Critical Contract Anomaly', 'Client description', 'Auditor rationale')
    """)
    conn.commit()
    conn.close()

def teardown_mock_data():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM advisor_findings WHERE analysis_run_id = 'RUN-999'")
    conn.commit()
    conn.close()

def test_premium_report_contract_structure(client):
    teardown_mock_data()
    setup_mock_data()
    
    res = client.get('/api/advisor/report/contract')
    assert res.status_code == 200
    data = res.json['data']
    
    assert 'report_id' in data
    assert 'company_id' in data
    assert 'financial_statements_snapshot' in data
    assert 'detailed_findings' in data
    
    findings = data['detailed_findings']
    assert len(findings) >= 1
    found = [f for f in findings if f['finding_id'] == 'finding-101'][0]
    assert found['title'] == 'Critical Contract Anomaly'
    assert found['plain_english_explanation'] == 'Client description'
    assert found['auditor_rationale'] == 'Auditor rationale'
    
    # Financial statements should have specific structure
    fs = data['financial_statements_snapshot']
    assert 'pnl_summary' in fs
    assert 'bs_summary' in fs
    assert 'cash_flow_summary' in fs

def test_premium_report_endpoints(client):
    # Test summary endpoint
    res = client.get('/api/advisor/report/summary?mode=client')
    assert res.status_code == 200
    assert 'summary_text' in res.json['data']
    
    # Test sections endpoint
    res = client.get('/api/advisor/report/sections')
    assert res.status_code == 200
    assert 'risk_register' in res.json['data']
    assert 'remediation_plan' in res.json['data']
    
    # Test appendix paging
    res = client.get('/api/advisor/report/appendix?page=1&per_page=10')
    assert res.status_code == 200
    assert 'pagination' in res.json
    assert res.json['pagination']['per_page'] == 10

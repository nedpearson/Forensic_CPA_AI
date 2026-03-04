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
    from database import init_db
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM advisor_findings WHERE analysis_run_id = 'RUN-999'")
    cursor.execute("""
        INSERT INTO advisor_findings 
        (company_id, finding_id, analysis_run_id, category, severity, confidence, title, plain_english_explanation, forensic_rationale) 
        VALUES 
        (999, 'finding-101', 'RUN-999', 'category-A', 'danger', 95, 'Critical Contract Anomaly', 'Client description', 'Auditor rationale')
    """)
    conn.commit()
    conn.close()

def test_export_audit_report_pdf(client):
    setup_mock_data()
    res = client.get('/api/export/audit_report?format=pdf&mode=client')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert b'PDF' in res.data[0:10]

def test_export_audit_report_docx(client):
    setup_mock_data()
    res = client.get('/api/export/audit_report?format=docx&mode=auditor')
    assert res.status_code == 200
    assert 'wordprocessingml.document' in res.headers['Content-Type']
    assert len(res.data) > 0
    
def test_export_single_finding(client):
    setup_mock_data()
    
    res = client.get('/api/export/finding/finding-101?format=pdf&mode=client')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert len(res.data) > 0

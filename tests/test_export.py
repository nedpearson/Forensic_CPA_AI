import pytest
from app import app
from database import get_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['active_company_id'] = 1 
            sess['company_role'] = 'owner'
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
        (1, 'finding-101', 'RUN-999', 'category-A', 'danger', 95, 'Critical Contract Anomaly', 'Client description', 'Auditor rationale')
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
    
    res = client.get(f'/api/export/finding/finding-101?format=pdf&mode=client')
    assert res.status_code == 200
    assert res.headers['Content-Type'] == 'application/pdf'
    assert len(res.data) > 0

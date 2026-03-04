import pytest
import json
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
    # Insert findings
    cursor.execute("""
        INSERT INTO advisor_findings 
        (company_id, finding_id, analysis_run_id, category, severity, confidence, title, recommended_actions) 
        VALUES 
        (999, 'finding-1', 'RUN-1', 'category-A', 'warning', 80, 'Test Finding 1', '["Action 1", "Action 2"]')
    """)
    conn.commit()
    conn.close()
    
    from database import sync_remediation_tasks
    # Fetch and sync
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM advisor_findings WHERE company_id = 999")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    # Must un-json the recommended_actions
    for r in rows:
        r['recommended_actions'] = json.loads(r['recommended_actions'])
        
    sync_remediation_tasks(999, rows)

def teardown_mock_data():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM advisor_remediation_tasks")
    cursor.execute("DELETE FROM advisor_findings")
    conn.commit()
    conn.close()

def test_sync_remediation_tasks():
    teardown_mock_data()
    setup_mock_data()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM advisor_remediation_tasks WHERE company_id = 999")
    tasks = cursor.fetchall()
    conn.close()
    
    assert len(tasks) == 2
    assert tasks[0]['task_description'] == 'Action 1'

def test_api_remediation_tasks(client):
    teardown_mock_data()
    setup_mock_data()
    
    res = client.get('/api/remediation/tasks')
    assert res.status_code == 200
    data = res.json['data']
    assert len(data) == 2
    assert data[0]['status'] == 'open'
    
def test_api_remediation_task_update(client):
    teardown_mock_data()
    setup_mock_data()
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM advisor_remediation_tasks WHERE company_id = 999 LIMIT 1")
    task_id = cursor.fetchone()['id']
    conn.close()
    
    res = client.put(f'/api/remediation/tasks/{task_id}', json={
        "status": "in-progress",
        "owner": "internal",
        "due_date": "2026-12-31"
    })
    
    assert res.status_code == 200
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT status, owner, due_date FROM advisor_remediation_tasks WHERE id = {task_id}")
    task = cursor.fetchone()
    conn.close()
    
    assert task['status'] == 'in-progress'
    assert task['owner'] == 'internal'
    assert task['due_date'] == '2026-12-31'

def test_re_audit_comparison(client):
    teardown_mock_data()
    setup_mock_data()
    
    # Add a second run that misses finding-1 but has finding-2
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO advisor_findings 
        (company_id, finding_id, analysis_run_id, category, severity, confidence, title, created_at) 
        VALUES 
        (999, 'finding-2', 'RUN-2', 'category-A', 'danger', 90, 'Test Finding 2', datetime('now', '+1 hour'))
    """)
    conn.commit()
    conn.close()
    
    res = client.get('/api/advisor/re_audit_status')
    assert res.status_code == 200
    data = res.json
    
    assert data['status'] == 'compared'
    assert data['previous_run_id'] == 'RUN-1'
    assert data['current_run_id'] == 'RUN-2'
    assert data['resolved_finding_ids'] == ['finding-1']

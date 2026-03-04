import os
import pytest
from flask import g
from werkzeug.security import generate_password_hash

from app import app
from database import init_db, get_db, DB_PATH

@pytest.fixture(scope="module")
def setup_test_client():
    os.environ['TESTING'] = 'true'
    app.config['TESTING'] = True
    client = app.test_client()
    
    # Initialize a clean database
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
    except Exception:
        pass
        
    init_db()
    
    # Create test users and companies manually
    conn = get_db()
    conn.execute("PRAGMA foreign_keys = OFF;")
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM companies")
    conn.execute("DELETE FROM company_users")
    conn.execute("PRAGMA foreign_keys = ON;")
    
    cursor = conn.cursor()
    hashed = generate_password_hash("password")
    
    # User 1 -> Company 1 (Owner)
    cursor.execute("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)", (1, "user1@example.com", hashed, "USER"))
    cursor.execute("INSERT INTO companies (id, name, created_by) VALUES (?, ?, ?)", (1, "Company Alpha", 1))
    cursor.execute("INSERT INTO company_users (company_id, user_id, role) VALUES (?, ?, ?)", (1, 1, "owner"))
    
    # User 2 -> Company 2 (Owner)
    cursor.execute("INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)", (2, "user2@example.com", hashed, "USER"))
    cursor.execute("INSERT INTO companies (id, name, created_by) VALUES (?, ?, ?)", (2, "Company Beta", 2))
    cursor.execute("INSERT INTO company_users (company_id, user_id, role) VALUES (?, ?, ?)", (2, 2, "owner"))
    
    conn.commit()
    conn.close()
    
    yield client
    
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
    except Exception:
        pass

def login(client, email, password="password"):
    return client.post('/api/auth/login', json={"email": email, "password": password})

def test_unauthenticated_access(setup_test_client):
    client = app.test_client() # completely fresh client
    res = client.get('/api/advisor/aggregate')
    assert res.status_code == 401

def test_missing_company_context(setup_test_client):
    client = setup_test_client
    # Log in
    res = login(client, "user1@example.com")
    assert res.status_code == 200
    
    # Call Advisor without company_id (header, query, or session)
    # The application defaults to 400 Bad Request if missing active company state
    res = client.get('/api/advisor/aggregate')
    assert res.status_code == 400
    
def test_authorized_company_access(setup_test_client):
    client = setup_test_client
    # Log in as User 1
    login(client, "user1@example.com")
    
    # Call Advisor with explicit permitted company_id block
    res = client.get('/api/advisor/aggregate?company_id=1')
    assert res.status_code == 200
    data = res.get_json()
    
    assert data['status'] == 'success'
    payload = data['data']
    
    # Check that payload structured dictionaries exist
    assert 'executive_summary' in payload
    assert 'risk_scoring' in payload
    assert 'fraud_red_flags' in payload
    assert 'scenario_simulator' in payload
    assert 'audit_ready_appendix' in payload
    
    # Check that payload was scoped correctly
    assert payload['company_id'] == 1

def test_cross_tenant_isolation(setup_test_client):
    client = setup_test_client
    # Log in as User 1
    login(client, "user1@example.com")
    
    # Attempt to hit Company 2 directly
    res = client.get('/api/advisor/aggregate?company_id=2')
    
    # Multi-tenant `@require_company_role` MUST block this with a 403 Forbidden
    assert res.status_code == 403
    assert b"Access restricted" in res.data or b"Forbidden" in res.data or res.status_code == 403

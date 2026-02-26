import os
import pytest
from flask import json
from app import app

@pytest.fixture(scope="module")
def setup_test_client():
    os.environ['TESTING'] = 'true'
    os.environ['ENABLE_INTEGRATIONS'] = 'true'
    os.environ['ENABLE_QB'] = 'true'
    os.environ['QUICKBOOKS_CLIENT_ID'] = 'mock_client_id'
    app.config['TESTING'] = True
    client = app.test_client()
    
    from database import init_db, get_db
    init_db()
    
    conn = get_db()
    conn.execute("PRAGMA foreign_keys = OFF;")
    conn.execute("DELETE FROM users")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.commit()
    
    from werkzeug.security import generate_password_hash
    cursor = conn.cursor()
    hashed = generate_password_hash("password")
    cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", ("user@example.com", hashed, "USER"))
    cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", ("admin@example.com", hashed, "ADMIN"))
    conn.commit()
    conn.close()
    
    yield client

def login(client, email, password="password"):
    return client.post('/api/auth/login', json={"email": email, "password": password})
    
def test_workspace_connect_user_denied(setup_test_client):
    client = setup_test_client
    login(client, "user@example.com")
    res = client.post('/api/integrations/quickbooks/connect')
    assert res.status_code == 403
    data = json.loads(res.data)
    assert "Forbidden" in data["error"]

def test_workspace_connect_admin_allowed(setup_test_client):
    client = setup_test_client
    login(client, "admin@example.com")
    res = client.post('/api/integrations/quickbooks/connect')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert "authorization_url" in data
    
def test_workspace_disconnect_user_denied(setup_test_client):
    client = setup_test_client
    login(client, "user@example.com")
    res = client.post('/api/integrations/quickbooks/disconnect')
    assert res.status_code == 403
    data = json.loads(res.data)
    assert "Forbidden" in data["error"]
    
def test_workspace_disconnect_admin_allowed(setup_test_client):
    client = setup_test_client
    login(client, "admin@example.com")
    res = client.post('/api/integrations/quickbooks/disconnect')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["status"] == "success"

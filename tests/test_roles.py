import os
import json
import pytest
from flask import Flask, jsonify, g
from werkzeug.security import generate_password_hash

from app import app, require_auth, require_admin, require_super_admin, User
    
# Add dummy routes for testing roles
@app.route('/api/test_auth', methods=['GET'])
@require_auth
def test_auth():
    return jsonify({"status": "ok", "role": getattr(g, 'user', User(0, '', 'none')).role})

@app.route('/api/test_admin', methods=['GET'])
@require_admin
def test_admin():
    return jsonify({"status": "ok"})

@app.route('/api/test_super', methods=['GET'])
@require_super_admin
def test_super():
    return jsonify({"status": "ok"})

@pytest.fixture(scope="module")
def setup_test_client():
    os.environ['TESTING'] = 'true'
    # We test app with normal request context
    app.config['TESTING'] = True
    client = app.test_client()
    
    # ensure db is initialized
    from database import init_db, get_db
    init_db()
    
    # clear users for pure test
    conn = get_db()
    conn.execute("DELETE FROM users")
    conn.commit()
    
    # Add dummy users directly
    cursor = conn.cursor()
    hashed = generate_password_hash("password")
    cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", ("user@example.com", hashed, "USER"))
    cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", ("admin@example.com", hashed, "ADMIN"))
    cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", ("super@example.com", hashed, "SUPER_ADMIN"))
    conn.commit()
    conn.close()
    
    yield client

def login(client, email, password="password"):
    return client.post('/api/auth/login', json={"email": email, "password": password})
    
def test_user_role(setup_test_client):
    client = setup_test_client
    
    # Login as normal user
    res = login(client, "user@example.com")
    assert res.status_code == 200
    
    # User can access auth route
    res = client.get('/api/test_auth')
    assert res.status_code == 200
    
    # User cannot access admin route
    res = client.get('/api/test_admin')
    assert res.status_code == 403
    
    # User cannot access super admin route
    res = client.get('/api/test_super')
    assert res.status_code == 403

def test_admin_role(setup_test_client):
    client = setup_test_client
    
    # Login as admin
    res = login(client, "admin@example.com")
    assert res.status_code == 200
    
    # Admin can access admin route
    res = client.get('/api/test_admin')
    assert res.status_code == 200
    
    # Admin cannot access super admin route
    res = client.get('/api/test_super')
    assert res.status_code == 403

def test_super_admin_role(setup_test_client):
    client = setup_test_client
    
    # Login as super admin
    res = login(client, "super@example.com")
    assert res.status_code == 200
    
    # Super admin can access admin route
    res = client.get('/api/test_admin')
    assert res.status_code == 200
    
    # Super admin can access super admin route
    res = client.get('/api/test_super')
    assert res.status_code == 200

def test_unauthenticated(setup_test_client):
    client = setup_test_client
    
    # explicitly logout (clear cookies)
    client.cookie_jar.clear()
    
    res = client.get('/api/test_auth')
    assert res.status_code == 401
    
    res = client.get('/api/test_admin')
    assert res.status_code == 401

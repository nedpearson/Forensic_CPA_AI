import pytest
from app import app
from database import get_db, create_user, clear_all_data

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        with app.app_context():
            yield client

import uuid

@pytest.fixture
def isolated_users():
    """Setup two users, each with their own isolated company/workspace."""
    # 1. Create users
    u1_email = f"u1_{uuid.uuid4().hex[:8]}@test.local"
    u2_email = f"u2_{uuid.uuid4().hex[:8]}@test.local"
    u1_id = create_user(u1_email, "pass")
    u2_id = create_user(u2_email, "pass")
    
    conn = get_db()
    cursor = conn.cursor()
    
    # 2. explicitly create workspace for u1
    cursor.execute("INSERT INTO companies (name, created_by, owner_user_id) VALUES (?, ?, ?)", ('C1', u1_id, u1_id))
    c1_id = cursor.lastrowid
    cursor.execute("INSERT INTO company_memberships (user_id, company_id, role, is_default) VALUES (?, ?, 'owner', 1)", (u1_id, c1_id))

    # 3. explicitly create workspace for u2
    cursor.execute("INSERT INTO companies (name, created_by, owner_user_id) VALUES (?, ?, ?)", ('C2', u2_id, u2_id))
    c2_id = cursor.lastrowid
    cursor.execute("INSERT INTO company_memberships (user_id, company_id, role, is_default) VALUES (?, ?, 'owner', 1)", (u2_id, c2_id))
    
    # 3. Add a test category to Company 1 to verify isolation
    cursor.execute("INSERT INTO categories (user_id, company_id, name) VALUES (?, ?, ?)", (u1_id, c1_id, 'C1_Secret_Cat'))
    
    conn.commit()
    conn.close()
    
    return {
        'u1': {'id': u1_id, 'company_id': c1_id, 'email': u1_email},
        'u2': {'id': u2_id, 'company_id': c2_id, 'email': u2_email}
    }

def test_missing_company_id_rejection(client, isolated_users):
    """If a session lacks an active_company_id but the user is logged in, decorators should bounce the request."""
    # Login but wipe the session active_company_id manually
    u1 = isolated_users['u1']
    client.post('/login', data={'email': u1['email'], 'password': 'pass'})
    
    with client.session_transaction() as sess:
        sess.pop('active_company_id', None)
        
    # Attempt to access a protected route
    resp = client.get('/api/categories')
    # Depending on how require_company_role acts, it might be 403 or 400
    assert resp.status_code in [400, 403]
    assert b"No active company" in resp.data or b"Unauthorized" in resp.data

def test_cross_tenant_spoofing_prevention(client, isolated_users):
    """User 1 tries to forcibly set their session company_id to User 2's company to steal data."""
    u1 = isolated_users['u1']
    u2 = isolated_users['u2']
    
    client.post('/login', data={'email': u1['email'], 'password': 'pass'})
    
    # Hack the session to point to the victim's company
    with client.session_transaction() as sess:
        sess['active_company_id'] = u2['company_id']
        
    # Attempt to read categories
    resp = client.get('/api/categories')
    
    # Must be unauthorized because user 1 lacks a membership record for company 2
    assert resp.status_code == 403

def test_tenant_data_isolation(client, isolated_users):
    """User 1 should see 'C1_Secret_Cat', User 2 should not."""
    u1 = isolated_users['u1']
    u2 = isolated_users['u2']
    
    # Check U1
    client.post('/login', data={'email': u1['email'], 'password': 'pass'})
    with client.session_transaction() as sess:
        sess['active_company_id'] = u1['company_id']
        
    resp1 = client.get('/api/categories')
    assert resp1.status_code == 200
    assert b"C1_Secret_Cat" in resp1.data
    
    client.get('/logout')
    
    # Check U2
    client.post('/login', data={'email': u2['email'], 'password': 'pass'})
    with client.session_transaction() as sess:
        sess['active_company_id'] = u2['company_id']
        
    resp2 = client.get('/api/categories')
    assert resp2.status_code == 200
    assert b"C1_Secret_Cat" not in resp2.data

def test_role_enforcement_viewer_mutation(client, isolated_users):
    """A viewer should not be able to POST new categories."""
    u1 = isolated_users['u1']
    u2 = isolated_users['u2']
    
    # Add User 2 to User 1's company as a viewer
    conn = get_db()
    conn.execute("INSERT INTO company_memberships (company_id, user_id, role) VALUES (?, ?, 'viewer')", (u1['company_id'], u2['id']))
    conn.commit()
    conn.close()
    
    client.post('/login', data={'email': u2['email'], 'password': 'pass'})
    
    with client.session_transaction() as sess:
        sess['active_company_id'] = u1['company_id']
        
    # Viewer tries to add a category
    resp = client.post('/api/categories', json={'name': 'Hacked_Cat'})
    
    # Should be blocked
    assert resp.status_code == 403

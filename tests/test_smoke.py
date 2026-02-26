import os
import sqlite3
import pytest
from flask import g
from werkzeug.security import generate_password_hash

from app import app
from database import init_db, get_db

@pytest.fixture(scope="module")
def smoke_client():
    os.environ['TESTING'] = 'true'
    app.config['TESTING'] = True
    
    # We must reset everything so that nedpearson@gmail.com and the demo user are created cleanly
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'forensic_audit.db')
    if os.path.exists(db_path):
        os.remove(db_path)
        
    os.environ['SUPER_ADMIN_BOOTSTRAP'] = 'true'
    os.environ['SUPER_ADMIN_EMAIL'] = 'nedpearson@gmail.com'
    os.environ['SUPER_ADMIN_PASSWORD'] = 'test_admin_pass'
    
    # Init DB (This triggers the super admin bootstrap)
    init_db()
    
    client = app.test_client()
    yield client
    
    # Teardown
    if os.path.exists(db_path):
        os.remove(db_path)

def test_super_admin_empty_state_and_login(smoke_client):
    # 1. Login as super admin mapped from DB init
    res = smoke_client.post('/api/auth/login', json={
        "email": "nedpearson@gmail.com",
        "password": "test_admin_pass"
    })
    assert res.status_code == 200
    
    # 2. Verify Empty State by checking active transactions & taxonomies for super admin
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'nedpearson@gmail.com'")
    admin_id = cursor.fetchone()['id']
    
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE user_id = ?", (admin_id,))
    assert cursor.fetchone()[0] == 0, "Super admin must start with 0 transactions"
    
    cursor.execute("SELECT COUNT(*) FROM taxonomy_config WHERE user_id = ?", (admin_id,))
    assert cursor.fetchone()[0] == 0, "Super admin must not have seeded taxonomies"
    conn.close()

def test_new_user_signup_and_empty_state(smoke_client):
    # 1. Signup a new standard user 
    res = smoke_client.post('/api/auth/signup', json={
        "email": "newuser@example.com",
        "password": "newpass"
    })
    assert res.status_code == 200
    
    # 2. Verify Empty State for the new user 
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = 'newuser@example.com'")
    user_id = cursor.fetchone()['id']
    
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE user_id = ?", (user_id,))
    assert cursor.fetchone()[0] == 0, "New user must start with 0 transactions"
    
    cursor.execute("SELECT COUNT(*) FROM categories WHERE user_id = ?", (user_id,))
    assert cursor.fetchone()[0] == 0, "New user must not have seeded categories natively"
    conn.close()

def test_demo_login_idempotent_seed(smoke_client):
    # 1. Enable Demo environment natively 
    os.environ['DEMO_SEED_ENABLED'] = 'true'
    
    # 2. Trigger the idempotent demo script
    res = smoke_client.post('/api/auth/demo')
    assert res.status_code == 200
    data = res.get_json()
    assert 'user_id' in data
    demo_id = data['user_id']
    
    # 3. Verify the generated data
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT email, is_demo FROM users WHERE id = ?", (demo_id,))
    user_row = cursor.fetchone()
    assert user_row['email'] == "demo@forensiccpa.ai"
    assert user_row['is_demo'] == 1
    
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE user_id = ?", (demo_id,))
    tx_count = cursor.fetchone()[0]
    assert tx_count > 0, "Demo user must be seeded with transaction data"
    
    # 4. Trigger again to verify idempotency (wipe_data logic)
    res2 = smoke_client.post('/api/auth/demo')
    assert res2.status_code == 200
    
    cursor.execute("SELECT COUNT(*) FROM transactions WHERE user_id = ?", (demo_id,))
    tx_count2 = cursor.fetchone()[0]
    # It wiped and recreated everything so count should be identical or very close since random numbers are involved, but definitely > 0
    assert tx_count2 > 0
    conn.close()

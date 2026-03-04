import app
from database import get_db

with app.app.test_client() as client:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT email FROM users LIMIT 1')
    user = cursor.fetchone()
    email = user['email']
    print('Testing with user:', email)

    # Login
    # Let's just use the demo login or login with test user
    # Or we can just use flask_login in a test request context
    with client.session_transaction() as sess:
        # We need to authenticate. Let's just use /api/demo/login to get a session
        pass
    
    r = client.post('/api/demo/login')
    print('Demo login:', r.status_code)
    
    r2 = client.post('/api/clear-data')
    print('Clear data:', r2.status_code, r2.data)

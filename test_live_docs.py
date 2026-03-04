import app
from flask_login import current_user

with app.app.test_client() as client:
    # Login as nedpearson@gmail.com
    r = client.post('/api/login', json={'email': 'nedpearson@gmail.com', 'password': '1Pearson2'})
    print('Login:', r.status_code)
    
    r2 = client.get('/api/documents')
    import json
    docs = json.loads(r2.data.decode('utf-8'))
    print("DOCUMENTS FOR NED:")
    for d in docs:
        print(f"ID: {d['id']}, Filename: {d['filename']}, User ID: {d.get('user_id')}")

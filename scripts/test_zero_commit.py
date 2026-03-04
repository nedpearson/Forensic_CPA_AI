import os
os.environ['TESTING'] = 'true'
os.environ['SUPER_ADMIN_BOOTSTRAP'] = 'true'
os.environ['SUPER_ADMIN_EMAIL'] = 'nedpearson@gmail.com'
os.environ['SUPER_ADMIN_PASSWORD'] = 'test_admin_pass'

from app import app
from database import init_db

init_db()

with app.test_client() as client:
    res = client.post('/api/auth/login', json={
        "email": "nedpearson@gmail.com",
        "password": "test_admin_pass"
    })
    print(f"Login: {res.status_code}")
    
    from app import upload_previews, _preview_lock
    import uuid
    preview_id = str(uuid.uuid4())[:8]
    with _preview_lock:
        upload_previews[preview_id] = {
            'transactions': [],
            'account_info': {'account_number': '', 'institution': 'Test'},
            'filename': 'test.pdf',
            'filepath': 'test.pdf',
            'ext': '.pdf',
            'doc_category': 'bank_statement',
            'zip_children_info': {},
            'file_hash': 'abcdef123456'
        }
        
    res = client.post('/api/upload/commit', json={'preview_id': preview_id, 'transactions': []})
    print(res.status_code)
    try:
        print(res.get_json())
    except:
        print(res.get_data(as_text=True))

import app
from database import get_documents, get_transactions
from flask_login import login_user
from database import get_user_by_email

with app.app.test_client() as client:
    # Login via route
    client.post('/api/login', json={'email': 'root@system.local', 'password': 'root'})

    r1 = client.post('/api/upload/preview', data={'file': (open('test.zip', 'rb'), 'test.zip')}, content_type='multipart/form-data')
    print("Preview code:", r1.status_code)
    try:
        d1 = r1.get_json()
        print("PREVIEW:", d1)
        req = {'preview_id': d1.get('preview_id'), 'transactions': d1.get('transactions')}
        r2 = client.post('/api/upload/commit', json=req)
        print("Commit Response:", r2.status_code, r2.get_json())
        
        docs = get_documents(5) # root is 5
        print("\nDOCUMENTS IN DB FOR ROOT:")
        for d in docs:
            print(f" - ID: {d['id']}, {d['filename']} (Parent: {d.get('parent_document_id')})")
            
        print("\nTRANSACTIONS:")
        txns = get_transactions(5)
        for t in txns: # root is 5
            print(f" - {t['description']} -> Doc ID: {t.get('document_id')}")

    except Exception as e:
        import traceback
        traceback.print_exc()


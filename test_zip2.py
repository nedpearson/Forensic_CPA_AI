import requests
import json

s = requests.Session()
r = s.post('http://127.0.0.1:5000/api/login', json={'email': 'root@system.local', 'password': 'root'})

with open('test.zip', 'rb') as f:
    files = {'file': ('test.zip', f, 'application/zip')}
    data = {'doc_type': 'auto', 'doc_category': 'bank_statement'}
    r1 = s.post('http://127.0.0.1:5000/api/upload/preview', files=files, data=data)
    print("Preview code:", r1.status_code)
    try:
        d1 = r1.json()
        print("PREVIEW:", d1)
        req = {'preview_id': d1.get('preview_id'), 'transactions': d1.get('transactions')}
        r2 = s.post('http://127.0.0.1:5000/api/upload/commit', json=req)
        print("Commit Response:", r2.status_code, r2.json())
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print("Raw Data:", r1.text)


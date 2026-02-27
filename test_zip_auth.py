import requests

s = requests.Session()
# standard form login
r = s.post('http://127.0.0.1:5000/login', data={'email': 'nedpearson@gmail.com', 'password': '1Pearson2'})
print("Login status:", r.status_code)

with open('test.zip', 'rb') as f:
    files = {'file': ('test.zip', f, 'application/zip')}
    data = {'doc_type': 'auto', 'doc_category': 'bank_statement'}
    r1 = s.post('http://127.0.0.1:5000/api/upload/preview', files=files, data=data)
    print("Preview code:", r1.status_code)
    try:
        d1 = r1.json()
        print(f"PREVIEW -> Trans Count: {d1.get('transaction_count')}, Preview ID: {d1.get('preview_id')}")
        req = {'preview_id': d1.get('preview_id'), 'transactions': d1.get('transactions')}
        r2 = s.post('http://127.0.0.1:5000/api/upload/commit', json=req)
        print("Commit Response:", r2.status_code, r2.json())
        
    except Exception as e:
        import traceback
        traceback.print_exc()


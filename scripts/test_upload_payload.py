import json
from urllib import request, parse

# 1. Login
data = parse.urlencode({'username': 'admin', 'password': 'password'}).encode()
req = request.Request('http://127.0.0.1:3006/login', data=data)
resp = request.urlopen(req)
cookie = resp.headers.get('Set-Cookie')

# 2. Preview
import io
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
body = (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="file"; filename="dummy.csv"\r\n'
    f'Content-Type: text/csv\r\n\r\n'
    f'Date,Description,Amount,Type\n2026-01-01,TEST UPLOAD,10.00,debit\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="doc_type"\r\n\r\n'
    f'csv\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="doc_category"\r\n\r\n'
    f'bank_statement\r\n'
    f'--{boundary}--\r\n'
).encode('utf-8')

req = request.Request('http://127.0.0.1:3006/api/upload/preview', data=body)
req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
req.add_header('Cookie', cookie)
resp = request.urlopen(req)
preview_data = json.loads(resp.read().decode('utf-8'))
preview_id = preview_data['preview_id']

# 3. Commit - Injecting cardholder_name directly to see if backend reads it
transactions = preview_data['transactions']
transactions[0]['cardholder_name'] = "Test User"
transactions[0]['card_last_four'] = "9999"

commit_data = {
    'preview_id': preview_id,
    'transactions': transactions
}

req = request.Request('http://127.0.0.1:3006/api/upload/commit', data=json.dumps(commit_data).encode('utf-8'))
req.add_header('Content-Type', 'application/json')
req.add_header('Cookie', cookie)
resp = request.urlopen(req)
print("Commit Status:", resp.getcode(), resp.read().decode())

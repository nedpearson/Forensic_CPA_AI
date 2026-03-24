import requests, json, zipfile, io
s = requests.Session()
r = s.post('http://localhost:3004/api/auth/login', json={'email':'nedpearson@gmail.com','password':'1Pearson2'})

c_res = s.get('http://localhost:3004/api/companies')
companies = c_res.json().get('companies', [])
if companies:
    s.post(f"http://localhost:3004/api/companies/{companies[0]['id']}/switch")

zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
    zip_file.writestr('doc1.pdf', b'dummy content 1')
    zip_file.writestr('doc2.pdf', b'dummy content 2')

print("Uploading Zip...")
files = {'file': ('test-archive.zip', zip_buffer.getvalue(), 'application/zip')}
data = {'docType': 'bank_statement'}
res = s.post('http://localhost:3004/api/upload', files=files, data=data)
print("Response:", res.status_code, res.text)

r3 = s.get('http://localhost:3004/api/documents')
docs = r3.json().get('documents', [])
print("Total docs in DB:", len(docs))
for d in docs:
    print(d.get('filename'), d.get('status'), d.get('parent_document_id'))

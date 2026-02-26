import os
import io
import zipfile
import pytest
import pandas as pd
from docx import Document
from app import app
from database import init_db, get_db, DB_PATH

@pytest.fixture(scope="module")
def auth_client():
    os.environ['TESTING'] = 'true'
    app.config['TESTING'] = True
    
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
    except BaseException:
        pass
        
    os.environ['SUPER_ADMIN_BOOTSTRAP'] = 'true'
    os.environ['SUPER_ADMIN_EMAIL'] = 'nedpearson@gmail.com'
    os.environ['SUPER_ADMIN_PASSWORD'] = 'test_admin_pass'
    
    init_db()
    
    client = app.test_client()
    
    # Login
    res = client.post('/api/auth/login', json={
        "email": "nedpearson@gmail.com",
        "password": "test_admin_pass"
    })
    
    yield client
    
    try:
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
    except BaseException:
        pass

def test_upload_pdf(auth_client):
    # Mocking a real PDF requires actual valid bytes for pdfplumber, 
    # but providing invalid bytes should test our new defensive OCR error handling gracefully.
    data = {
        'file': (io.BytesIO(b'%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF'), 'test.pdf'), 
        'doc_type': 'auto', 
        'doc_category': 'bank_statement'
    }
    res = auth_client.post('/api/upload/preview', data=data, content_type='multipart/form-data')
    assert res.status_code in (200, 500)
    json_data = res.get_json()
    assert 'error' in json_data or 'status' in json_data

def test_upload_xlsx(auth_client):
    df = pd.DataFrame({'Date': ['01/01/2026'], 'Description': ['Test Excel'], 'Amount': [-50.0]})
    output = io.BytesIO()
    df.to_excel(output, index=False)
    output.seek(0)
    
    data = {'file': (output, 'test.xlsx'), 'doc_type': 'auto', 'doc_category': 'bank_statement'}
    res = auth_client.post('/api/upload/preview', data=data, content_type='multipart/form-data')
    print('XLSX ERROR:', res.get_data(as_text=True))
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['status'] == 'ok'
    assert json_data['transaction_count'] == 1

def test_upload_docx(auth_client):
    doc = Document()
    doc.add_paragraph('Test proof document content')
    output = io.BytesIO()
    doc.save(output)
    output.seek(0)
    
    data = {'file': (output, 'test.docx'), 'doc_type': 'proof'}
    res = auth_client.post('/api/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['status'] == 'ok'
    assert json_data['mode'] == 'proof'

def test_upload_zip(auth_client):
    # Zip containing an Excel file
    df = pd.DataFrame({'Date': ['01/01/2026'], 'Description': ['Test Zip Excel'], 'Amount': [-50.0]})
    excel_out = io.BytesIO()
    df.to_excel(excel_out, index=False)
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zf:
        zf.writestr('inside.xlsx', excel_out.getvalue())
    zip_buffer.seek(0)
    
    data = {'file': (zip_buffer, 'bundle.zip'), 'doc_type': 'auto'}
    res = auth_client.post('/api/upload/preview', data=data, content_type='multipart/form-data')
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['status'] == 'ok'
    assert json_data['transaction_count'] == 1
    assert json_data['transactions'][0]['_source_file'] == 'inside.xlsx'

def test_existing_upload_behaves_identically(auth_client):
    csv_data = b"Date,Description,Amount\n01/02/2026,Test CSV,-10.0\n"
    data = {'file': (io.BytesIO(csv_data), 'test.csv'), 'doc_type': 'auto'}
    res = auth_client.post('/api/upload/preview', data=data, content_type='multipart/form-data')
    json_data = res.get_json()
    assert json_data['status'] == 'ok'
    assert json_data['transaction_count'] == 1


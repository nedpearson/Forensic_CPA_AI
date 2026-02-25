import os
import json
import pytest

# Required to load environment correctly with mock tokens
os.environ['UPLOAD_AUTH_TOKEN'] = 'secret-test-token'
os.environ['AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT'] = 'https://mock.cognitiveservices.azure.com/'
os.environ['AZURE_DOCUMENT_INTELLIGENCE_KEY'] = 'mock-key'

from app import app
from database import init_db, get_db

@pytest.fixture(scope="module")
def setup_test_client():
    os.environ['TESTING'] = 'true'
    init_db()
    # Provide a simple text file to simulate an upload
    test_file_path = 'test_upload.pdf'
    with open(test_file_path, 'wb') as f:
        f.write(b'%PDF-1.4 mock pdf data')
        
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client
        
    # Cleanup
    if os.path.exists(test_file_path):
        os.remove(test_file_path)

def test_api_docs_upload_unauthorized(setup_test_client):
    client = setup_test_client
    response = client.post('/api/docs/upload')
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Unauthorized'

def test_api_docs_upload_success(setup_test_client, mocker):
    client = setup_test_client
    
    # Mock the Azure adapter to avoid network calls during tests
    mock_analyze = mocker.patch('document_analyzer.AzureDocumentIntelligenceAdapter.analyze_document')
    mock_analyze.return_value = {"content": "mock extracted content", "pages": []}
    
    with open('test_upload.pdf', 'rb') as f:
        data = {'file': (f, 'test_upload.pdf')}
        headers = {'Authorization': 'Bearer secret-test-token'}
        response = client.post('/api/docs/upload', data=data, headers=headers)
        
    assert response.status_code == 202
    json_data = response.get_json()
    assert 'document_id' in json_data
    assert 'extraction_id' in json_data
    
    doc_id = json_data['document_id']
    
    # Wait for the background thread to finish
    import time
    time.sleep(0.5)
    
    # Verify extraction record
    ext_response = client.get(f'/api/docs/{doc_id}/extraction')
    assert ext_response.status_code == 200
    ext_data = ext_response.get_json()
    assert ext_data['status'] == 'completed'
    assert 'content' in ext_data['extraction_data']
    assert ext_data['extraction_data']['content'] == 'mock extracted content'

def test_api_docs_get(setup_test_client):
    client = setup_test_client
    # Let's get the doc we just uploaded (should be ID 1 if DB is clean)
    response = client.get('/api/docs/1')
    assert response.status_code == 200
    assert response.get_json()['filename'] == 'test_upload.pdf'

import os
import json
import pytest

from database import init_db, get_db, add_document, add_document_extraction
from auto_categorizer import AutoCategorizer
from llm_provider import LLMProvider
from pydantic import BaseModel
from typing import Dict, Any, Type
from app import app

# --- Mock Provider ---
class MockLLMProvider(LLMProvider):
    def generate_structured_output(self, prompt: str, schema_model: Type[BaseModel]) -> Dict[str, Any]:
        return {
            "risk_categories": [
                {"category_name": "High Wire Transfer Velocity", "confidence": 0.95, "justification": "Saw huge wire"}
            ],
            "entities": [
                {"name": "J. Doe", "type": "person", "canonical_name": "John Doe", "confidence": 0.88}
            ],
            "topics": ["offshore banking", "fraud"],
            "summary": "Document details wires [Page 1].",
            "key_findings": ["Found John Doe wire."]
        }

@pytest.fixture(scope="module")
def setup_test_client():
    os.environ['TESTING'] = 'true'
    # Mock Auth for API endpoints
    os.environ['UPLOAD_AUTH_TOKEN'] = 'secret-test-token'
    
    init_db()
    
    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO users (id, email, password_hash, role) VALUES (1, 'test@test.com', 'hash', 'USER')")
    conn.commit()
    conn.close()
    
    # Pre-seed a document extraction
    doc_id = add_document(1, 'test_statement.pdf', '/fake/path.pdf', 'pdf', 'bank_statement', None)
    ext_id = add_document_extraction(1, doc_id, status='completed')
    
    # Update extraction with some dummy JSON data
    conn = get_db()
    conn.execute("UPDATE document_extractions SET extraction_data = ? WHERE id = ?", 
                 ('{"content": "WIRE TRANSFER $500,000 J. Doe"}', ext_id))
    conn.commit()
    conn.close()
    
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client, doc_id

def test_auto_categorizer_logic():
    mock_provider = MockLLMProvider()
    categorizer = AutoCategorizer(provider=mock_provider)
    
    result = categorizer.run_categorization("Dummy text", taxonomy=[])
    
    assert 'risk_categories' in result
    assert result['risk_categories'][0]['category_name'] == 'High Wire Transfer Velocity'
    assert result['entities'][0]['canonical_name'] == 'John Doe'

def test_api_categorize_endpoint(setup_test_client, mocker):
    client, doc_id = setup_test_client
    
    def sync_thread(target, args=()):
        target(*args)
        class DummyThread:
            def start(self): pass
        return DummyThread()
    mocker.patch('threading.Thread', side_effect=sync_thread)
    
    # Mock the Categorizer inside the app thread to use our Mock provider
    mock_categorizer = mocker.patch('app.AutoCategorizer')
    mock_instance = mock_categorizer.return_value
    mock_instance.provider = MockLLMProvider()
    mock_instance.run_categorization.return_value = MockLLMProvider().generate_structured_output("", None)
    
    # Manually trigger categorization
    headers = {'Authorization': 'Bearer secret-test-token'}
    response = client.post(f'/api/docs/{doc_id}/categorize', headers=headers)
    
    assert response.status_code == 202
    assert response.get_json()['status'] == 'accepted'
    
    # Wait for background thread
    # time.sleep(0.5) (Removed since thread is sync)
    
    # Retrieve Categorization
    cat_response = client.get(f'/api/docs/{doc_id}/categorization', headers=headers)
    assert cat_response.status_code == 200
    
    data = cat_response.get_json()
    assert data['status'] == 'completed'
    assert data['model'] == 'unknown'  # Mock doesn't declare model attribute explicitly
    assert 'categorization_data' in data
    
    parsed_cat = data['categorization_data']
    assert len(parsed_cat['entities']) == 1
    assert parsed_cat['entities'][0]['canonical_name'] == 'John Doe'

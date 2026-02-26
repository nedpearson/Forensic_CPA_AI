import os
import pytest
import sqlite3
import base64
from shared.encryption import encrypt_token, decrypt_token, get_cipher
from database import init_db, upsert_integration, get_integration, get_db

@pytest.fixture(autouse=True)
def setup_encryption_env():
    # Provide a consistent 32-byte key for testing
    test_key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    os.environ['OAUTH_ENCRYPTION_KEY'] = test_key
    yield test_key
    os.environ.pop('OAUTH_ENCRYPTION_KEY', None)

@pytest.fixture
def memory_db():
    import database
    original_db = database.DB_PATH
    
    test_db_path = os.path.join(os.path.dirname(__file__), 'test_integrations.db')
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
        
    database.DB_PATH = test_db_path
    database.init_db()
    
    yield
    
    database.DB_PATH = original_db
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except Exception:
            pass

def test_encryption_wrapper_cipher():
    # Test symmetrical AES string logic
    plain_text = "test_sensitive_token_12345"
    encrypted = encrypt_token(plain_text)
    
    assert encrypted != plain_text
    assert isinstance(encrypted, str)
    
    decrypted = decrypt_token(encrypted)
    assert decrypted == plain_text

def test_encryption_wrapper_missing_key():
    del os.environ['OAUTH_ENCRYPTION_KEY']
    with pytest.raises(ValueError, match="OAUTH_ENCRYPTION_KEY environment variable is missing"):
        get_cipher()

def test_encryption_wrapper_invalid_key():
    os.environ['OAUTH_ENCRYPTION_KEY'] = "invalid_key_length"
    with pytest.raises(ValueError, match="Invalid OAUTH_ENCRYPTION_KEY format"):
        get_cipher()

def test_integration_token_db_storage(memory_db):
    user_id = 1
    provider = "google"
    access_token = "mock_access_token_abc"
    refresh_token = "mock_refresh_token_xyz"
    
    encrypted_access = encrypt_token(access_token)
    encrypted_refresh = encrypt_token(refresh_token)
    
    upsert_integration(
        user_id=user_id,
        provider=provider,
        status="Connected",
        scopes=['read_drive', 'read_calendar'],
        access_token=encrypted_access,
        refresh_token=encrypted_refresh
    )
    
    record = get_integration(user_id, provider)
    assert record is not None
    assert record['status'] == "Connected"
    assert record['provider'] == provider
    assert "read_drive" in record['scopes']
    
    # Assert DB stored encrypted strings
    assert record['access_token'] == encrypted_access
    assert record['access_token'] != access_token
    
    # Assert they decode safely
    assert decrypt_token(record['access_token']) == access_token
    assert decrypt_token(record['refresh_token']) == refresh_token

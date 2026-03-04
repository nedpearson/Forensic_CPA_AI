import pytest
import sqlite3
import json
import base64
import os
import sys
import datetime
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from shared.quickbooks_client import QuickBooksOAuthService
from shared.quickbooks_sync import QuickBooksSyncService
from shared.quickbooks_webhooks import QuickBooksWebhookService
import database

# Mock functions for secrets/encryption
def mock_encrypt(val):
    return b"enc_" + val.encode()

def mock_decrypt(val):
    if isinstance(val, bytes):
        val = val.decode()
    return val.replace("enc_", "")

@pytest.fixture(autouse=True)
def setup_teardown(monkeypatch):
    monkeypatch.setenv("DB_DIALECT", "sqlite")
    monkeypatch.setenv("QUICKBOOKS_CLIENT_ID", "test_client_id")
    monkeypatch.setenv("QUICKBOOKS_CLIENT_SECRET", "test_client_secret")
    monkeypatch.setenv("QUICKBOOKS_WEBHOOK_TOKEN", "test_webhook_token")
    monkeypatch.setenv("QUICKBOOKS_REDIRECT_URI", "https://localhost/cb")
    monkeypatch.setenv("QUICKBOOKS_ENVIRONMENT", "sandbox")
    monkeypatch.setattr("shared.quickbooks_client.encrypt_token", mock_encrypt)
    monkeypatch.setattr("shared.quickbooks_client.decrypt_token", mock_decrypt)
    monkeypatch.setattr("shared.quickbooks_client.json.dumps", json.dumps)
    
    # We will use the existing db if possible or mock the db conn.
    # To be safe, we'll patch `get_db` to return an in-memory db that has the schema initialized.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    
    # Init minimal tables
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT);
        CREATE TABLE companies (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE integrations (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            company_id INTEGER,
            provider TEXT,
            status TEXT,
            access_token TEXT,
            refresh_token TEXT,
            scopes TEXT,
            expires_at INTEGER,
            refresh_token_expires_at INTEGER,
            metadata TEXT,
            account_name TEXT,
            last_error TEXT,
            last_sync_completed_at TIMESTAMP,
            last_successful_webhook_at TIMESTAMP,
            connected_at TIMESTAMP,
            updated_at TIMESTAMP
        );
        CREATE UNIQUE INDEX idx_integrations_company_provider ON integrations(company_id, provider);
        CREATE TABLE fcpa_sync_jobs (id INTEGER PRIMARY KEY);
        CREATE TABLE sync_jobs (
            id INTEGER PRIMARY KEY,
            company_id INTEGER,
            provider TEXT,
            sync_type TEXT,
            status TEXT,
            error_message TEXT,
            records_processed INTEGER,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            user_id INTEGER
        );
        CREATE TABLE fcpa_categories (id INTEGER PRIMARY KEY);
        CREATE TABLE categories (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            company_id INTEGER,
            name TEXT,
            category_type TEXT,
            source_provider TEXT,
            source_entity_type TEXT,
            source_entity_id TEXT,
            source_realm_id TEXT,
            synced_at TIMESTAMP,
            raw_metadata TEXT
        );
        CREATE TABLE merchants (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            company_id INTEGER,
            canonical_name TEXT,
            source_provider TEXT,
            source_entity_type TEXT,
            source_entity_id TEXT,
            source_realm_id TEXT,
            synced_at TIMESTAMP,
            raw_metadata TEXT,
            is_business INTEGER
        );
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            company_id INTEGER,
            trans_date TEXT,
            amount REAL,
            trans_type TEXT,
            description TEXT,
            source_provider TEXT,
            source_entity_type TEXT,
            source_entity_id TEXT,
            source_realm_id TEXT,
            synced_at TIMESTAMP,
            raw_metadata TEXT
        );
        CREATE TABLE quickbooks_webhooks (
            id INTEGER PRIMARY KEY,
            realm_id TEXT,
            webhook_payload TEXT,
            status TEXT,
            retry_count INTEGER,
            error_message TEXT,
            created_at TIMESTAMP,
            updated_at TIMESTAMP
        );
    """)
    conn.execute("INSERT INTO users (id, email) VALUES (1, 'test@test.com')")
    conn.execute("INSERT INTO companies (id, name) VALUES (1, 'Test Company')")
    # A base integration
    conn.execute("""
        INSERT INTO integrations (user_id, company_id, provider, status, access_token, refresh_token, metadata) 
        VALUES (1, 1, 'quickbooks', 'Connected', 'enc_valid_access', 'enc_valid_refresh', '{"realmId": "12345"}')
    """)
    class MockConn:
        def __init__(self, c):
            self.c = c
        def cursor(self, *args, **kwargs): return self.c.cursor(*args, **kwargs)
        def commit(self, *args, **kwargs): return self.c.commit(*args, **kwargs)
        def close(self): pass
        def execute(self, *args, **kwargs): return self.c.execute(*args, **kwargs)
        def executescript(self, *args, **kwargs): return self.c.executescript(*args, **kwargs)
        def rollback(self, *args, **kwargs): return self.c.rollback(*args, **kwargs)
        @property
        def row_factory(self): return self.c.row_factory
        @row_factory.setter
        def row_factory(self, val): self.c.row_factory = val

    mock_c = MockConn(conn)

    def mock_get_db():
        return mock_c

    # Replace getting connection at module levels where imported
    import shared.quickbooks_sync
    import shared.quickbooks_webhooks
    import database_sqlite
    
    monkeypatch.setattr(database, "get_db", mock_get_db)
    monkeypatch.setattr(database_sqlite, "get_db", mock_get_db)
    monkeypatch.setattr(shared.quickbooks_sync, "get_db", mock_get_db)
    monkeypatch.setattr(shared.quickbooks_webhooks, "get_db", mock_get_db)
    
    yield
    # No conn.close() here as it messes up SQLite in-memory with threading across mocks sometimes,
    # or it is closed properly by GC when conn goes out of scope.

def test_oauth_url_generation_success():
    # URL generates correctly with proper params
    url = QuickBooksOAuthService.buildQuickBooksAuthUrl(state='some-state-1-1')
    assert url.startswith("https://appcenter.intuit.com/connect/oauth2")
    assert "state=some-state-1-1" in url
    assert "client_id=test_client_id" in url
    assert "response_type=code" in url
    assert "scope=com.intuit.quickbooks.accounting" in url
    assert "redirect_uri=https%3A%2F%2Flocalhost%2Fcb" in url

def test_oauth_url_strips_query_string(monkeypatch):
    monkeypatch.setenv("QUICKBOOKS_REDIRECT_URI", "https://localhost/cb?extra_param=123")
    url = QuickBooksOAuthService.buildQuickBooksAuthUrl(state='valid-state')
    assert "redirect_uri=https%3A%2F%2Flocalhost%2Fcb" in url
    assert "extra_param" not in url

def test_oauth_fails_if_env_missing(monkeypatch):
    monkeypatch.delenv("QUICKBOOKS_CLIENT_ID", raising=False)
    with pytest.raises(ValueError, match="Missing required QuickBooks environment variables"):
        QuickBooksOAuthService.buildQuickBooksAuthUrl(state='some-state-1-1')

def test_oauth_fails_on_placeholders(monkeypatch):
    monkeypatch.setenv("QUICKBOOKS_CLIENT_ID", "your_qb_id")
    with pytest.raises(ValueError, match="Invalid placeholder or default value detected"):
        QuickBooksOAuthService.buildQuickBooksAuthUrl(state='some-state-1-1')

def test_token_refresh_flow(monkeypatch):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
        def json(self): return self.json_data
        def raise_for_status(self): pass
        
    def mock_post(*args, **kwargs):
        return MockResponse({
            "access_token": "new_acc",
            "refresh_token": "new_ref",
            "expires_in": 3600,
            "x_refresh_token_expires_in": 8640000
        }, 200)

    monkeypatch.setattr("requests.post", mock_post)
    
    # We first update DB to expire the access token but keep refresh token valid
    conn = database.get_db()
    conn.execute("UPDATE integrations SET expires_at=0, refresh_token_expires_at=9999999999 WHERE provider='quickbooks'")
    conn.commit()

    # Now get valid access token should trigger refresh
    # We need to mock get_integration for simplistic db
    def mock_get_int(*args, **kwargs):
        c = database.get_db().cursor()
        r = c.execute("SELECT * FROM integrations WHERE provider='quickbooks'").fetchone()
        return dict(r) if r else None
        
    monkeypatch.setattr("shared.quickbooks_client.get_integration", mock_get_int)
    from database import upsert_integration
    def mock_upsert(*args, **kwargs):
        c = database.get_db().cursor()
        c.execute("UPDATE integrations SET access_token=?, refresh_token=?, expires_at=? WHERE provider='quickbooks'", 
                  (b"enc_new_acc", b"enc_new_ref", kwargs.get('expires_at')))
        database.get_db().commit()
    monkeypatch.setattr("database.upsert_integration", mock_upsert)

    acc = QuickBooksOAuthService.getValidAccessToken(1, 1)
    assert acc == "new_acc"

def test_idempotent_upsert():
    # Test that inserting an entity twice doesn't duplicate
    QuickBooksSyncService._upsert_category(1, 1, "12345", {"Id": "100", "Name": "Test Acc", "AccountType": "Bank"})
    QuickBooksSyncService._upsert_category(1, 1, "12345", {"Id": "100", "Name": "Test Acc Update", "AccountType": "Bank"})
    
    conn = database.get_db()
    cats = conn.execute("SELECT * FROM categories WHERE source_entity_id='100'").fetchall()
    assert len(cats) == 1
    assert cats[0]["name"] == "Test Acc Update"

def test_realm_resolution():
    integration = QuickBooksWebhookService.resolve_integration("12345")
    assert integration is not None
    assert integration["company_id"] == 1
    
    integration2 = QuickBooksWebhookService.resolve_integration("99999")
    assert integration2 is None

def test_webhook_logging():
    QuickBooksWebhookService.log_webhook("12345", '{"test": 1}')
    conn = database.get_db()
    rows = conn.execute("SELECT * FROM quickbooks_webhooks").fetchall()
    assert len(rows) == 1
    assert rows[0]["realm_id"] == "12345"

def test_webhook_signature():
    # Intuit uses HMAC SHA256 base64. 
    # Token is test_webhook_token
    payload = b'{"eventNotifications":[]}'
    import hmac, hashlib
    hashed = hmac.new(b"test_webhook_token", payload, hashlib.sha256).digest()
    sig = base64.b64encode(hashed).decode('utf-8')
    assert QuickBooksWebhookService.validate_signature(sig, payload) == True
    assert QuickBooksWebhookService.validate_signature("invalid", payload) == False

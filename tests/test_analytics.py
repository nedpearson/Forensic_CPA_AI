import sqlite3
import pytest
import os
from database import init_db, get_db
from query_builder import QueryBuilder
from app import app

# Setup test DB
@pytest.fixture(scope="module")
def setup_database():
    # Use a test db to not pollute the real db
    os.environ['TESTING'] = 'true'
    init_db()
    conn = get_db()
    try:
        conn.execute('PRAGMA foreign_keys = OFF;')
        conn.execute('DELETE FROM transactions')
        conn.execute('PRAGMA foreign_keys = ON;')
        
        # Insert some dummy transactions
        conn.execute('''
            INSERT INTO transactions (user_id, trans_date, description, amount, category, cardholder_name, is_personal, is_business, is_transfer, trans_type)
            VALUES 
            (1, '2023-01-01', 'Test Business 1', -100.0, 'Business - Supplies', 'Alice', 0, 1, 0, 'debit'),
            (1, '2023-01-02', 'Test Business 2', -200.0, 'Business - Services', 'Bob', 0, 1, 0, 'debit'),
            (1, '2023-01-03', 'Test Personal 1', -50.0, 'Personal - Dining', 'Alice', 1, 0, 0, 'debit'),
            (1, '2023-01-04', 'Test Deposit', 500.0, 'Deposits', NULL, 0, 0, 0, 'credit')
        ''')
        conn.commit()
    finally:
        conn.close()
        
    yield
    # Teardown logic if needed

def test_query_builder_where_clause():
    # Test empty filters
    qb = QueryBuilder(1, {})
    where, params = qb.get_where_clause()
    assert where == "user_id = ?"
    assert len(params) == 1

    # Test view mode
    qb = QueryBuilder(1, {'view_mode': 'business'})
    where, params = qb.get_where_clause()
    assert where == "user_id = ? AND is_business = 1"
    
    # Test exact matches
    qb = QueryBuilder(1, {'cardholder': 'Alice', 'category': 'Personal - Dining'})
    where, params = qb.get_where_clause()
    assert "user_id = ?" in where
    assert "cardholder_name = ?" in where
    assert "category = ?" in where
    assert "Alice" in params
    assert "Personal - Dining" in params

def test_query_builder_faceted_counts(setup_database):
    qb = QueryBuilder(1, {'view_mode': 'business'})
    conn = get_db()
    counts = qb.get_faceted_counts(conn)
    conn.close()
    
    # Check we only see business categories and cardholders
    categories = {c['label']: c['count'] for c in counts['categories']}
    assert 'Business - Supplies' in categories
    assert 'Business - Services' in categories
    assert 'Personal - Dining' not in categories
    
    cardholders = {c['label']: c['count'] for c in counts['cardholders']}
    assert cardholders['Alice'] == 1
    assert cardholders['Bob'] == 1

def test_api_analytics_overview(setup_database):
    os.environ['UPLOAD_AUTH_TOKEN'] = 'secret-test-token'
    client = app.test_client()
    headers = {'Authorization': 'Bearer secret-test-token'}
    response = client.get('/api/analytics/overview?view_mode=business', headers=headers)
    assert response.status_code == 200
    data = response.get_json()
    assert 'facets' in data
    assert 'timeline' in data
    assert 'top_entities' in data
    
    # Check top entities matches the data inserted
    entities = [e['entity'] for e in data['top_entities']]
    assert 'Test Business 2' in entities
    assert 'Test Business 1' in entities
    assert 'Test Personal 1' not in entities

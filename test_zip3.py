import app
from database import get_documents, get_transactions, get_db

with app.app.test_client() as client:
    # 1. Login
    client.post('/api/auth/login', json={'email': 'nedpearson@gmail.com', 'password': '1Pearson2'})

    # 2. Upload zip
    with open('test.zip', 'rb') as f:
        r1 = client.post('/api/upload/preview', data={
            'file': (f, 'test.zip'),
            'doc_type': 'auto',
            'doc_category': 'bank_statement'
        }, content_type='multipart/form-data')
        
    d1 = r1.get_json()
    prev_id = d1.get('preview_id')
    print('Preview transactions:', d1.get('transaction_count'))
    
    # 3. Commit
    r2 = client.post('/api/upload/commit', json={'preview_id': prev_id, 'transactions': d1.get('transactions')})
    res2 = r2.get_json()
    print('Commit Response:', r2.status_code, res2)
    doc_id = res2.get('document_id')
    
    # Display state before approve
    docs = get_documents(1) # 1 is nedpearson
    print("\n[BEFORE APPROVE] Documents:")
    for d in docs:
        if 'test' in d['filename']:
            print(f"- ID {d['id']}, {d['filename']}, Parsed: {d['parsed_transaction_count']}, Imported: {d['import_transaction_count']}")
            
    # 4. Approve
    r3 = client.post(f'/api/documents/{doc_id}/approve')
    print('\nApprove Response:', r3.status_code, r3.get_json())
    
    # 5. Check transactions
    # Note: user_id for nedpearson might be 1, let's use 1 instead of 7
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, description, document_id, is_approved FROM transactions WHERE user_id = 1")
    txns = c.fetchall()
    conn.close()
    
    print("\n[AFTER APPROVE] Transactions:")
    for t in txns:
        if 'test' in str(t['description']).lower() or 'demo' in str(t['description']).lower() or 'fake' in str(t['description']).lower():
            print(f"- ID {t['id']}, Desc: {t['description']}, Doc: {t['document_id']}, Approved: {t['is_approved']}")
            

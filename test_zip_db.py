import os
import zipfile
import uuid
from database import get_db, add_document, add_transaction, get_documents, get_transactions

os.makedirs('test_zip_dir2', exist_ok=True)
with open('test_zip_dir2/doc3.csv', 'w') as f:
    f.write('Date,Description,Amount,Type\n2023-01-01,Test 3,10.0,debit\n')

with zipfile.ZipFile('test2.zip', 'w') as z:
    z.write('test_zip_dir2/doc3.csv', 'doc3.csv')

user_id = 7 # nedpearson

# Mock Preview State
transactions = [{
    'trans_date': '2023-01-01',
    'description': 'Test 3',
    'amount': 10.0,
    '_source_hash': 'mockhash123',
    'trans_type': 'debit',
    'category': 'Uncategorized'
}]
zip_children_info = {'mockhash123': 'doc3.csv'}

# 1. Save Document Record
parent_doc_id = add_document(
    user_id=user_id,
    filename='test2.zip',
    original_path='test2.zip',
    file_type='zip',
    doc_category='bank_statement',
    account_id=None,
    content_sha256='zipphash123'
)

child_doc_map = {}

# 2. Save transactions and children
added = 0
for trans in transactions:
    target_doc_id = parent_doc_id
    child_hash = trans.get('_source_hash')
    if child_hash:
        if child_hash not in child_doc_map:
            c_filename = zip_children_info.get(child_hash, 'extracted_pdf')
            c_ext = c_filename.rsplit('.', 1)[1].lower() if '.' in c_filename else 'pdf'
            c_id = add_document(
                user_id=user_id,
                filename=c_filename,
                original_path=None,
                file_type=c_ext,
                doc_category='bank_statement',
                account_id=None,
                content_sha256=child_hash,
                parent_document_id=parent_doc_id
            )
            child_doc_map[child_hash] = c_id
            print(f"Created child doc ID {c_id} for {c_filename}")
        target_doc_id = child_doc_map[child_hash]

    trans_id, is_new = add_transaction(
        user_id=user_id,
        doc_id=target_doc_id,
        account_id=None,
        trans_date=trans['trans_date'],
        post_date=trans['trans_date'],
        description=trans['description'],
        amount=trans['amount'],
        trans_type=trans['trans_type'],
        category=trans['category']
    )
    print(f"Added Transaction {trans_id} to Document {target_doc_id}")
    
# Verification
docs = get_documents(user_id)
txns = get_transactions(user_id)

print("\n--- RESULTS ---")
print("DOCUMENTS:")
for d in docs:
    if 'test2' in d['filename'] or 'doc3.csv' in d['filename']:
        print(f" - ID: {d['id']}, Name: {d['filename']}, Parent: {d.get('parent_document_id')}")

print("\nTRANSACTIONS:")
for t in txns:
    if t['description'] == 'Test 3':
        print(f" - ID: {t['id']}, Desc: {t['description']}, Doc ID: {t.get('document_id')}")


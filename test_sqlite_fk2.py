import sqlite3
import traceback
from database import delete_document, get_db

conn = sqlite3.connect('data/forensic_audit.db')
conn.execute('PRAGMA foreign_keys = ON')

try:
    with conn:
        conn.execute('INSERT INTO accounts (user_id, account_name, account_type) VALUES (4, "test", "bank")')
        acc_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        conn.execute('INSERT INTO documents (user_id, filename, file_type) VALUES (4, "test.pdf", "pdf")')
        doc1 = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        conn.execute('INSERT INTO documents (user_id, filename, file_type) VALUES (4, "test2.pdf", "pdf")')
        doc2 = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Insert a transaction pointing to doc1
        conn.execute('''INSERT INTO transactions (user_id, document_id, account_id, trans_date, description, amount, trans_type) 
                     VALUES (4, ?, ?, "2023-01-01", "test", 10.0, "debit")''', (doc1, acc_id))
        txn_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Link transaction to both docs in transaction_sources
        conn.execute('INSERT INTO transaction_sources (user_id, transaction_id, document_id) VALUES (4, ?, ?)', (txn_id, doc1))
        conn.execute('INSERT INTO transaction_sources (user_id, transaction_id, document_id) VALUES (4, ?, ?)', (txn_id, doc2))
        
        print("Setup done.")
except BaseException:
    pass

# Call the actual implementation
success = delete_document(4, doc1)
if success:
    print('Document deleted successfully.')
else:
    print('Failed to delete document.')

with get_db() as c:
    c.execute('DELETE FROM transactions WHERE description = "test"')
    c.execute('DELETE FROM documents WHERE filename LIKE "test%.pdf"')
    c.execute('DELETE FROM accounts WHERE account_name = "test"')

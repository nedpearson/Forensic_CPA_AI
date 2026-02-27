import sqlite3
import traceback

conn = sqlite3.connect('data/forensic_audit.db')
conn.execute('PRAGMA foreign_keys = ON')

try:
    with conn:
        conn.execute('INSERT INTO accounts (user_id, account_name, account_type) VALUES (1, "test", "bank")')
        acc_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        conn.execute('INSERT INTO documents (user_id, filename, file_type) VALUES (1, "test.pdf", "pdf")')
        doc1 = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        conn.execute('INSERT INTO documents (user_id, filename, file_type) VALUES (1, "test2.pdf", "pdf")')
        doc2 = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Insert a transaction pointing to doc1
        conn.execute('''INSERT INTO transactions (user_id, document_id, account_id, trans_date, description, amount) 
                     VALUES (1, ?, ?, "2023-01-01", "test", 10.0)''', (doc1, acc_id))
        txn_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Link transaction to both docs in transaction_sources
        conn.execute('INSERT INTO transaction_sources (user_id, transaction_id, document_id) VALUES (1, ?, ?)', (txn_id, doc1))
        conn.execute('INSERT INTO transaction_sources (user_id, transaction_id, document_id) VALUES (1, ?, ?)', (txn_id, doc2))
        
        print("Setup done.")
        
        # Now try to delete doc1 Using delete_document logic!
        # 3. Delete from transaction_sources
        conn.execute(f"DELETE FROM transaction_sources WHERE document_id IN (?) AND user_id = 1", (doc1,))
        
        # 4. Remove orphan transactions
        conn.execute("""
            DELETE FROM transactions 
            WHERE user_id = 1 
            AND id NOT IN (SELECT transaction_id FROM transaction_sources WHERE user_id = 1)
        """)
        
        # 5. Delete documents
        conn.execute(f"DELETE FROM documents WHERE id IN (?) AND user_id = 1", (doc1,))
        
        print("Success!")
except Exception as e:
    traceback.print_exc()
finally:
    # Cleanup
    with conn:
        conn.execute('DELETE FROM transactions WHERE description = "test"')
        conn.execute('DELETE FROM documents WHERE filename LIKE "test%.pdf"')
        conn.execute('DELETE FROM accounts WHERE account_name = "test"')

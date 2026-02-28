import sqlite3
from database import get_db, delete_document, add_document

def test_delete():
    conn = get_db()
    cursor = conn.cursor()
    
    # get root user
    cursor.execute("SELECT id FROM users LIMIT 1")
    user = cursor.fetchone()
    if not user:
        print("No users found.")
        return
    user_id = user['id']
    
    doc_id = add_document(user_id, "test_doc.csv", "", "csv", "bank_statement", conn=conn)
    cursor.execute("INSERT INTO transactions (user_id, document_id, trans_date, description, amount) VALUES (?, ?, '2023-01-01', 'Test', 10)", (user_id, doc_id))
    trans_id = cursor.lastrowid
    cursor.execute("INSERT INTO transaction_sources (user_id, transaction_id, document_id) VALUES (?, ?, ?)", (user_id, trans_id, doc_id))
    conn.commit()
    
    # Try deleting it
    try:
        success = delete_document(user_id, doc_id)
        if success:
            print(f"Success deleting doc {doc_id}")
        else:
            print(f"Failed deleting doc {doc_id} but no exception")
    except Exception as e:
        print(f"Exception deleting doc: {e}")
        
if __name__ == '__main__':
    test_delete()

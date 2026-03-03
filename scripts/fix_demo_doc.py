import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db

with app.app_context():
    conn = get_db()
    cursor = conn.cursor()
    # Find the document for Company 2 that is queued
    cursor.execute("UPDATE documents SET status = 'approved', parsed_transaction_count = 91, import_transaction_count = 91 WHERE filename LIKE '%Demo_Bank_Statement%'")
    conn.commit()
    print("Updated mock documents to approved.")

import sqlite3
import traceback

conn = sqlite3.connect('data/forensic_audit.db')
conn.execute('PRAGMA foreign_keys = ON')

user_id = 4 # Or 1, we can just find any user

try:
    with conn:
        conn.executescript(f\"\"\"
            DELETE FROM proof_links WHERE user_id = {user_id};
            DELETE FROM audit_log WHERE user_id = {user_id};
            DELETE FROM transactions WHERE user_id = {user_id};
            DELETE FROM documents WHERE user_id = {user_id};
            DELETE FROM accounts WHERE user_id = {user_id};
            DELETE FROM case_notes WHERE user_id = {user_id};
            DELETE FROM saved_filters WHERE user_id = {user_id};
        \"\"\")
        print("Success!")
except Exception as e:
    traceback.print_exc()

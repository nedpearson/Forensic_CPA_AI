import sqlite3
import pandas as pd

conn = sqlite3.connect('data/forensic_audit.db')

print("USERS:")
print(pd.read_sql_query("SELECT id, email, role, is_demo FROM users", conn))

print("\nDOCUMENTS:")
print(pd.read_sql_query("SELECT id, user_id, filename FROM documents", conn))


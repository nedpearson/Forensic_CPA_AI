import sqlite3
import pandas as pd
from database import DB_PATH

pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)

conn = sqlite3.connect(DB_PATH)

print('--- Last 10 Documents ---')
df_docs = pd.read_sql("SELECT id, filename, parent_document_id, parsed_transaction_count, import_transaction_count FROM documents ORDER BY id DESC LIMIT 10", conn)
print(df_docs)

print('\n--- Children of Zip ---')
df_children = pd.read_sql("SELECT id, filename, parsed_transaction_count, import_transaction_count FROM documents WHERE parent_document_id = (SELECT id FROM documents WHERE filename LIKE '%EStatement%' ORDER BY id DESC LIMIT 1)", conn)
print(df_children)

conn.close()

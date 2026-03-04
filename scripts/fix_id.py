import re

with open('database_pg.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Automatically append RETURNING id to all basic INSERT statements
text = re.sub(
    r'(?i)(INSERT\s+INTO\s+[\w_]+\s*\([^)]+\)\s*VALUES\s*\([^)]+\))(["\'])', 
    r'\1 RETURNING id\2', 
    text
)

# Replace cursor.lastrowid
text = text.replace('cursor.lastrowid', "cursor.fetchone()['id']")

# Remove the recursive duplicate close_db that gets generated from SQLite's helpers
bad_close_db = '''
def close_db(conn):
    if conn:
        close_db(conn)
'''
text = text.replace(bad_close_db, '')

# Also handle "RETURNING id" being duplicated inside scripts if run twice
text = text.replace('RETURNING id RETURNING id', 'RETURNING id')

with open('database_pg.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("Properly patched lastrowid and RETURNING id.")

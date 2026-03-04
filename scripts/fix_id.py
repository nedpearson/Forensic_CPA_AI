import os

with open('database_pg.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace all occurrences of wrongly escaped strings
new_text = text.replace(r"\'id\'", "'id'")

with open('database_pg.py', 'w', encoding='utf-8') as f:
    f.write(new_text)

print("Fixed database_pg.py successfully.")

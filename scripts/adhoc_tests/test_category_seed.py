import database
database.init_db()
conn = database.get_db()
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM categories WHERE user_id = ?', (1,))
count = cursor.fetchone()[0]
print(f'Root user seeded categories: {count}')
cursor.execute('SELECT name, scope, tax_deductible_default, reimbursable_default FROM categories WHERE parent_category_id IS NOT NULL LIMIT 5')
for row in cursor.fetchall():
    print(dict(row))
conn.close()

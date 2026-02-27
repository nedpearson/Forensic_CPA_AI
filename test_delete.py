import traceback
from database import clear_all_data, delete_document, get_db

conn = get_db()
cursor = conn.cursor()
cursor.execute('SELECT id FROM users LIMIT 1')
user = cursor.fetchone()
if not user:
    print('No user')
    exit()

u_id = user['id']
print('Testing clear_all_data for user', u_id)
try:
    clear_all_data(u_id)
    print('clear_all_data Success')
except Exception as e:
    print('clear_all_data FAILED:')
    traceback.print_exc()


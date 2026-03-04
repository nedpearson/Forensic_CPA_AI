import requests

s = requests.Session()
# 1. Login
r = s.post('http://127.0.0.1:5000/api/login', json={'email': 'root@system.local', 'password': 'root'})
print('Login:', r.status_code, r.text)

# 2. Clear data
r2 = s.post('http://127.0.0.1:5000/api/clear-data')
print('Clear Data:', r2.status_code, r2.text)


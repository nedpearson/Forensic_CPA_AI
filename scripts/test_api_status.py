import sys
import os
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app

app.config['TESTING'] = True

print("Authenticating as demo user...")
with app.test_client() as client:
    resp = client.post('/api/auth/demo')
    if resp.status_code != 200:
        print("Login failed!")
        sys.exit(1)
        
    client.post('/api/business/switch', json={'company_id': 1})
        
    print("Checking /api/advisor/status...")
    response = client.get('/api/advisor/status')
    print(f"Status Code: {response.status_code}")
    print(json.dumps(response.get_json(), indent=2))

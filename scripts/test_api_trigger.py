import sys
import os
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from database import get_db

app.config['TESTING'] = True

print("Triggering /api/advisor/aggregate API logic...")
with app.test_client() as client:
    # Set the session so current_user logic succeeds
    with client.session_transaction() as sess:
        sess['user_id'] = 1  
        
    response = client.get('/api/advisor/aggregate')
    print(f"Status Code: {response.status_code}")
    print(json.dumps(response.get_json(), indent=2))

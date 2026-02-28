import json
from app import app
from categorizer import get_cardholder_comparison

with app.app_context():
    data = get_cardholder_comparison(7)
    print("Cardholder Comparison Output for User 7:")
    print(json.dumps(data, indent=2))

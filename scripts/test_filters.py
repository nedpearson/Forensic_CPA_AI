import sys
import os
import json
from app import app, get_transactions

def test_api():
    with app.app_context():
        filters = {}
        txns = get_transactions(1, filters)
        print(f"Empty filters returned {len(txns)} transactions")
        
        filters = {'date_from': '2024-01-01'}
        txns_date = get_transactions(1, filters)
        print(f"Date filters returned {len(txns_date)} transactions")

if __name__ == '__main__':
    test_api()

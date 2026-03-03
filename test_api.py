from app import app
with app.test_client() as client:
    with client.session_transaction() as sess:
        sess['active_company_id'] = 1
        sess['_user_id'] = '1'
    res = client.get('/api/advisor/aggregate')
    print('Status:', res.status_code)
    try:
        print('JSON Keys:', res.json.keys() if res.json else 'None')
    except: pass

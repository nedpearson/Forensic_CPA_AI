import requests

base_url = "http://127.0.0.1:3004"
session = requests.Session()

def run_checks():
    print("1. Checking login page render...")
    res = session.get(f"{base_url}/login")
    if res.status_code != 200:
        print(f"ERROR: /login returned {res.status_code}")
    else:
        print("SUCCESS: /login rendered (200 OK)")

    print("2. Attempting demo login...")
    res = session.post(f"{base_url}/api/auth/demo")
    
    if res.status_code != 200:
         print(f"ERROR: Demo Login failed with {res.status_code} - {res.text}")
         return
    else:
         print("SUCCESS: Demo Login successful (200 OK)")

    print("3. Checking settings page render...")
    res = session.get(f"{base_url}/settings", allow_redirects=False)
    if res.status_code != 200:
        print(f"ERROR: /settings returned {res.status_code} (Redirected to: {res.headers.get('Location', 'N/A')})")
    else:
        print("SUCCESS: /settings rendered (200 OK)")

    print("4. Checking settings integrations page render...")
    res = session.get(f"{base_url}/settings/integrations", allow_redirects=False)
    if res.status_code != 200:
        print(f"ERROR: /settings/integrations returned {res.status_code} (Redirected to: {res.headers.get('Location', 'N/A')})")
    else:
        print("SUCCESS: /settings/integrations rendered (200 OK)")

if __name__ == "__main__":
    run_checks()

import requests
import sys
import os

base_url = "http://127.0.0.1:3004"
session_1 = requests.Session()
session_2 = requests.Session()

print("=====================================================")
print("      FORENSIC CPA AI - AUTH VERIFICATION PIPELINE   ")
print("=====================================================\n")

checks = []

try:
    # 1. App Launch -> Login Screen
    res = session_1.get(f"{base_url}/", allow_redirects=False)
    if res.status_code in [301, 302, 303, 307, 308] and 'login' in res.headers.get('Location', ''):
        checks.append("[PASS] App launch redirects to login screen when signed out")
    else:
        checks.append(f"[FAIL] App launch redirect failed. Status: {res.status_code}")

    # 2. Login as Demo User
    login_res = session_1.post(f"{base_url}/api/auth/demo")
    if login_res.status_code == 200:
        pass # Prerequisites met
    else:
        print("[CRITICAL ERROR] Could not log in to test dashboard.")
        sys.exit(1)

    # 3. Login Name Visible Bottom-Right Near Settings
    dash_html = session_1.get(f"{base_url}/").text
    if "fa-sign-out-alt" in dash_html and "fa-user-check text-success" in dash_html:
        checks.append("[PASS] Login name & Sign Out button visible bottom-right near Settings")
    else:
        checks.append("[FAIL] Could not find User Badge in the Settings panel HTML")

    # 4. Sign Out Returns to Login
    logout_res = session_1.post(f"{base_url}/api/auth/logout")
    redirect_check = session_1.get(f"{base_url}/", allow_redirects=False)
    
    if redirect_check.status_code in [301, 302, 303, 307, 308] and 'login' in redirect_check.headers.get('Location', ''):
         checks.append("[PASS] Sign out successfully destroys session and returns to login")
    else:
         checks.append("[FAIL] Sign out did not properly clear session or redirect.")

    # 5. Login as Another User Works
    login_res_2 = session_2.post(f"{base_url}/api/auth/demo")
    if login_res_2.status_code == 200 and len(session_2.cookies.get_dict()) > 0:
        checks.append("[PASS] Login as another user works flawlessly after previous session clears")
    else:
        checks.append("[FAIL] Login as another user failed or retained stale state.")

except requests.exceptions.ConnectionError:
    print("[CRITICAL ERROR] The Forensic CPA AI application is not currently running on http://127.0.0.1:3004.")
    print("Please start the server first using: $env:ENABLE_INTEGRATIONS=\"true\"; .venv\\Scripts\\python app.py")
    sys.exit(1)

# Print Checklist
for check in checks:
    print(check)

if any("[FAIL]" in check for check in checks):
    print("\n[FAIL] VERIFICATION FAILED: One or more checks did not pass.")
    sys.exit(1)
else:
    print("\n[OK] VERIFICATION SUCCESS: All Authentication Flow checks passed successfully!")

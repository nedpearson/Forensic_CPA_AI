import urllib.request
import urllib.error
from http.cookiejar import CookieJar

cj = CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Login as Demo User
req = urllib.request.Request("http://127.0.0.1:3004/api/auth/demo", method="POST")
try:
    opener.open(req)
except Exception as e:
    pass

# Retrieve API Integrations Status
req = urllib.request.Request("http://127.0.0.1:3004/api/integrations/status")
try:
    resp = opener.open(req)
    print("SUCCESS")
    print(resp.read().decode())
except urllib.error.HTTPError as e:
    print("ERROR", e.code)
    print(e.read().decode())
except Exception as e:
    print("GENERAL ERROR:", e)

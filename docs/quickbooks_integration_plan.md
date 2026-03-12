# QuickBooks Real Integration — Viability & Implementation Plan

## TL;DR — Current Status

> **90% of the work is already done.** The backend is fully implemented. The only blockers are Intuit's formal production approval process and two environment variable changes.

---

## What's Already Built ✅

| Component | File | Status |
|---|---|---|
| OAuth 2.0 Authorization URL builder | `shared/quickbooks_client.py` | ✅ Done |
| Token exchange (code → access/refresh) | `shared/quickbooks_client.py` | ✅ Done |
| Encrypted token storage (Fernet) | `shared/encryption.py` | ✅ Done |
| Automatic token refresh | `shared/quickbooks_client.py` | ✅ Done |
| Full sync engine (Accounts, Customers, Vendors, Transactions) | `shared/quickbooks_sync.py` | ✅ Done |
| Webhook listener for real-time updates | `shared/quickbooks_webhooks.py` | ✅ Done |
| OAuth Connect endpoint | `app.py` `/api/integrations/quickbooks/connect` | ✅ Done |
| OAuth Callback endpoint | `app.py` `/api/integrations/quickbooks/callback` | ✅ Done |
| Sync Data endpoint | `app.py` `/api/integrations/quickbooks/sync` | ✅ Done |
| Disconnect endpoint | `app.py` `/api/integrations/quickbooks/disconnect` | ✅ Done |
| Test Connection endpoint | `app.py` `/api/integrations/quickbooks/test` | ✅ Done |
| Intuit Developer App (credentials exist) | `.env` `QUICKBOOKS_CLIENT_ID` | ✅ Exists |

---

## What's Blocking ❌

### 1. Intuit App Status — Sandbox only
The app registered on Intuit's developer portal is currently in **Sandbox** mode. This means it only works for test companies, not real QuickBooks accounts.

**Action required:**
- Go to [developer.intuit.com](https://developer.intuit.com) → Your App → **Production** tab
- Fill out the **App Assessment Questionnaire** (15–30 questions about data usage, security, privacy)
- Submit for Intuit's review

**Intuit's review timeline:** ~3–10 business days (can be accelerated with a support ticket)

### 2. Production Redirect URI not registered
The Intuit developer portal requires you to whitelist exact redirect URIs. The production URI `https://cpa.sisifoai.com/api/integrations/quickbooks/callback` must be added.

### 3. Two `.env` changes needed on the server
```diff
- QUICKBOOKS_ENVIRONMENT=sandbox
+ QUICKBOOKS_ENVIRONMENT=production

- QUICKBOOKS_CLIENT_ID=ABqFqnIqJw7...   # sandbox key
+ QUICKBOOKS_CLIENT_ID=<production_key_from_intuit_portal>
+ QUICKBOOKS_CLIENT_SECRET=<production_secret_from_intuit_portal>
```

---

## Step-by-Step Activation Plan

### Phase 1 — Intuit Portal (1–2 days of prep)
1. **Log in** to [developer.intuit.com](https://developer.intuit.com) with Ned's Intuit account
2. Navigate to **Dashboard → Your App → Production**
3. Add redirect URI: `https://cpa.sisifoai.com/api/integrations/quickbooks/callback`
4. Complete the **App Assessment** form:
   - Data usage: accounting/bookkeeping (read + write transactions)
   - Security: HTTPS enforced, tokens encrypted at rest (Fernet), stored in DB only
   - Privacy: data processed on private server, not shared with third parties
5. Submit and wait for approval email (~3–10 business days)

### Phase 2 — Server Config (30 minutes, after approval)
```bash
ssh root@cpa.sisifoai.com
nano /var/www/Forensic_CPA_AI/.env
```
Update these 3 values with the credentials from the Intuit Production tab:
```
QUICKBOOKS_CLIENT_ID=<production_client_id>
QUICKBOOKS_CLIENT_SECRET=<production_client_secret>
QUICKBOOKS_ENVIRONMENT=production
```
Then restart:
```bash
systemctl restart forensic_cpa_ai
```

### Phase 3 — End-to-End Test (15 minutes)
1. Log in as a real user at `cpa.sisifoai.com`
2. Go to **Settings → Integrations → QuickBooks → Connect**
3. You'll be redirected to Intuit's real authorization page
4. Log in with a real QuickBooks company account
5. Authorize the app
6. Return to the dashboard — click **Sync Data**
7. Verify real transactions appear in All Transactions

### Phase 4 — Demo Mode Cleanup (optional, after production works)
Once production is live, we can remove the "Use Demo" bypass code from `app.py` and `shared/quickbooks_sync.py`, or keep it as a fallback for sales demos.

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| Intuit rejects app assessment | Low (30%) | App is legitimate accounting software — follow their security checklist |
| Webhook delivery fails in prod | Medium | Polling fallback already implemented in sync engine |
| Token theft via DB breach | Low | Tokens are Fernet-encrypted at rest |
| User connects wrong QB company | Low | Disconnect + reconnect flow already works |

---

## Effort Estimate

| Task | Effort |
|---|---|
| Fill Intuit app assessment form | 2–3 hours |
| Wait for Intuit approval | 3–10 business days |
| Update 3 env vars on server | 10 minutes |
| End-to-end testing | 1 hour |
| **Total dev effort** | **~4 hours** (excl. Intuit wait time) |

---

## Bottom Line

The integration is production-ready from an engineering standpoint. The only dependency is a regulatory/approval process from Intuit that no amount of code can bypass. Once approved, going live is **3 environment variable changes and a server restart**.

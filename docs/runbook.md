# Forensic CPA AI - Operational Runbook

This document outlines the standard operating procedures, environment requirements, and troubleshooting steps for deploying and maintaining the Forensic CPA AI application on Render.

## 1. Deployment Overview
The application is deployed via Render Blueprint (`render.yaml`).
- **Environment:** Python 3.10+
- **Web Server:** Gunicorn (`gunicorn app:app`)
- **Database:** SQLite (mounted on a persistent disk if using persistent data, or ephemeral if purely stateless with external DB).
- **Pre-Deploy Hook:** Database schema initialization runs automatically during the build/deploy phase (`python -c "import database; database.init_db()"`).

## 2. Environment Variables Checklist
Ensure the following environment variables are set in the Render Dashboard:

| Variable | Requirement | Description |
|---|---|---|
| `FLASK_ENV` | Required | Set to `production` |
| `SESSION_SECRET` | Required | Cryptographic secret for browser sessions |
| `COOKIE_SECURE` | Required | Set to `true` to ensure Secure flags on browser cookies for production |
| `DATABASE_URL` | Optional | Connection string if using PostgreSQL instead of SQLite |
| `OPENAI_API_KEY` | Required | Key for LLM analytics and auto-categorization |
| `AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT`| Optional | For PDF bank statement extraction |
| `AZURE_DOCUMENT_INTELLIGENCE_KEY` | Optional | For PDF bank statement extraction |
| `UPLOAD_AUTH_TOKEN` | Optional | Bearer token required for API-driven headless uploads |
| `DEMO_SEED_ENABLED` | Optional | Set to `true` to allow the `/api/auth/demo` endpoint to generate an ephemeral demo account |

## 3. Health & Smoke Testing
The application exposes two probes for uptime monitoring:

**Liveness Probe (`GET /api/health`)**
Returns a 200 OK immediately if the web server is running. Used by Render to route traffic.

**Readiness/Smoke Probe (`GET /api/smoke`)**
Performs a deep check on infrastructure:
1. Executes a basic analytics query counting transactions and categories gracefully in the database.
2. Verifies presence of AI/LLM credentials.
3. Checks authentication security configs (`COOKIE_SECURE`, `SESSION_SECRET`, and `DEMO_SEED_ENABLED`).
4. Returns `503 Service Unavailable` if the DB is unreachable, preventing broken deployments from going live.

*To run a manual smoke test locally in PowerShell (for verification parity):*
```powershell
# 1. Start the server (if not already running)
# $env:FLASK_APP="app.py"; $env:FLASK_ENV="development"; python -m flask run

# 2. Check Health
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health"

# 3. Check Deep Smoke (Formats JSON output for readability)
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/smoke" -Method GET | ConvertTo-Json -Depth 5
```

*To run a manual smoke test against a live Render instance via curl:*
```bash
curl -i https://your-render-url.onrender.com/api/smoke
```

## 4. Common Failures and Resolution

### Symptom: `503` or `500` on `/api/smoke` after deployment
**Cause 1: Database Migration Failure**
- **Action:** Check the "Deploy" logs in Render. Verify that the `preDeployCommand` executed successfully. If using SQLite on an ephemeral disk, ensure the deployment process initializes the schema correctly.
**Cause 2: Missing Credentials**
- **Action:** `smoke` will return a JSON payload indicating which check failed. Verify `OPENAI_API_KEY` is set in the Render environment variables tab.

### Symptom: Uploads are stalling or failing
**Cause: Azure Document Intelligence Timeout/Config**
- **Action:** Check application logs for the specific `request_id`. Look for timeouts reaching Azure. Verify your Azure resource hasn't hit its Free Tier quota limits.

### Symptom: Auto-categorization is unhelpful
**Cause: LLM Rate Limiting**
- **Action:** Search the structured logs in Render for `Status: 429` reaching OpenAI. If occurring frequently, upgrade the OpenAI tier or implement backoff strategies in `auto_categorizer.py`.

## 5. Log Searching
All logs are emitted to STDOUT in structured format including `request_id` and `latency`.
To trace a user's upload error:
1. Find the upload request in Render Logs: `POST /api/docs/upload`.
2. Copy the `req_id: [UUID]` from the log line.
3. Search the logs for that exact UUID to see all subsequent parsing, extraction, and categorization steps tied to that specific transaction.

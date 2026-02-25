# Forensic CPA AI - Operational Runbook (Render Deployment)

## Overview
This runbook details the deployment, configuration, and troubleshooting steps for the Forensic CPA AI application running on [Render](https://render.com).

## Environment Variables Checklist
The following environment variables MUST be configured in your Render dashboard for the web service:
- `PYTHON_VERSION`: `3.11.0` (Ensures compatibility with all dependency native bindings)
- `DB_PATH`: `/data/forensic_audit.db` (Mapped to the persistent disk)
- `LLM_API_KEY`: (Secret) OpenAI API key for auto-categorization and extraction.
- `AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT`: (Secret) Azure DI endpoint URL.
- `AZURE_DOCUMENT_INTELLIGENCE_KEY`: (Secret) Azure DI API key.
- `UPLOAD_AUTH_TOKEN`: (Secret) Bearer token for securing document uploads and categorizations.

## Smoke Test Procedure
After every deployment, verify the system health using the `/api/smoke` endpoint:
1. Navigate to `https://<your-render-url>/api/smoke`
2. Expected Response (HTTP 200 OK):
```json
{
  "status": "pass",
  "checks": {
    "database": {
      "status": "ok",
      "row_count": 0
    },
    "azure_di": {
      "status": "configured"
    },
    "llm_provider": {
      "status": "configured",
      "provider": "openai"
    }
  }
}
```

## Common Failures & Fixes

### 1. Database is resetting on every deploy (Data Loss)
**Symptom**: Transactions and documents disappear when Render spins up a new instance.
**Cause**: The application is writing `forensic_audit.db` to ephemeral storage instead of the persistent disk.
**Fix**: Verify that the `render.yaml` disk is mounted at `/data` and the environment variable `DB_PATH` is explicitly set to `/data/forensic_audit.db`.

### 2. Smoke Test returns HTTP 503
**Symptom**: Checking `/api/smoke` returns `status: "fail"` and `missing_credentials: true`.
**Cause**: The Azure DI or LLM API keys are missing from the Render Environment settings.
**Fix**: Navigate to Render Dashboard -> Web Service -> Environment. Ensure the `sync: false` keys from `render.yaml` have been manually populated with real secrets.

### 3. Uploads timeout (HTTP 502 / 504)
**Symptom**: Large PDFs fail to upload or analyze.
**Cause**: Gunicorn's default synchronous workers are timing out reading the payload.
**Fix**: Gunicorn is configured via `.venv`. Check the application logs. Uploads and parsing invoke background threading to mitigate this, but if the web node runs out of memory (Render Free Tier constraints), consider upgrading the memory allocation or adjusting Gunicorn timeout options `gunicorn app:app -b 0.0.0.0:$PORT -t 120`.

### 4. Background processing failing silently
**Symptom**: Document extraction remains "pending" forever.
**Cause**: The background thread threw an exception (e.g., Azure API rejected the payload) and wasn't cleanly caught to update the database state, or the application instance was suspended by Render before the thread finished.
**Fix**: 
1. Check the structured logs: Search for `[ERROR]` or `req_id: system` identifying unhanded thread crashes.
2. If Render is suspending your instance (Free Tier), background tasks won't complete when no HTTP requests are keeping the instance awake. Consider upgrading to a unified continuous web worker.

### Log Viewing
Render streams logs via stdout. The application uses structured logging:
`2026-02-25 15:42:01 [INFO] [req_id:4b50d-21fa...] POST /api/docs/upload - Status: 202 - Latency: 45.2ms`
Filter by `req_id` to trace an entire request lifespan across upload, extraction, and categorization.

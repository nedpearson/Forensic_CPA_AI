# Render Deployment Notes: Super Admin Bootstrap

To securely provision the root `SUPER_ADMIN` account on Render without committing sensitive credentials to the repository, we use deterministic environment variables.

## Required Environment Variables
In your Render Dashboard (Environment tab), configure the following **Secret Files & Environment Variables**:

1. `SUPER_ADMIN_BOOTSTRAP` = `true`
2. `SUPER_ADMIN_EMAIL` = `nedpearson@gmail.com`
3. `SUPER_ADMIN_PASSWORD` = `<your-secure-password-here>`

## How It Works
During cold starts (when Gunicorn launches Flask inside `app.py`), the `init_db()` hook inside `database.py` evaluates these variables.

1. **If missing:** The app boots normally.
2. **If present:** The app verifies if `nedpearson@gmail.com` exists.
   - If **NO**, it creates the user with an empty-state (0 demo cases, 0 default taxonomies) and assigns the `SUPER_ADMIN` role. 
   - If **YES** but the role is mismatched or password changed, it aggressively enforces the state lock: Updating the `role = 'SUPER_ADMIN'` and resetting the password hash.

## Validating Deployment
After your Render deploy succeeds, the system will output a confirmation log directly in the Render Events container logs:
```plaintext
Super admin verified: nedpearson@gmail.com created.
# or
Super admin verified: nedpearson@gmail.com updated to SUPER_ADMIN.
```

To programmatically verify your role payload after signing into `https://your-render-url.com/login` with your new credentials, navigate to `/api/admin/verify`. 

You should receive a `200 OK` response:
```json
{
    "email": "nedpearson@gmail.com",
    "message": "Super admin verified",
    "status": "success",
    "user_id": 1
}
```

## Running Locally
For local development and testing, you can provision the admin account deterministically by running the PowerShell helper script in your workspace:
```powershell
.\scripts\seed_super_admin.ps1
```

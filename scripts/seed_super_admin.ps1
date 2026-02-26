<#
.SYNOPSIS
    Locally bootstraps the SUPER_ADMIN account using the .env file.
.DESCRIPTION
    This script loads the SUPER_ADMIN_BOOTSTRAP, SUPER_ADMIN_EMAIL, and SUPER_ADMIN_PASSWORD
    variables (or overrides them temporarily) to provision the root user deterministically.
.EXAMPLE
    .\scripts\seed_super_admin.ps1
#>

Write-Host "Starting SUPER_ADMIN Bootstrap..." -ForegroundColor Cyan

# Force the environment variables just for this script's execution
$env:SUPER_ADMIN_BOOTSTRAP = "true"
if (-Not $env:SUPER_ADMIN_EMAIL) {
    # Provide defaults to test if the .env lacks them
    $env:SUPER_ADMIN_EMAIL = "nedpearson@gmail.com"
}
if (-Not $env:SUPER_ADMIN_PASSWORD) {
    $env:SUPER_ADMIN_PASSWORD = "local_dev_password_123"
}

# Run the DB initialization hook which triggers the bootstrap sequence logic inside init_db()
python -c "from database import init_db; init_db()"

Write-Host "Done!" -ForegroundColor Green

@echo off
title Forensic CPA AI Server
echo Starting Forensic CPA AI...
cd /d "%~dp0"

:: Activate virtual environment
if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
) else (
    echo Virtual environment not found in .venv!
    pause
    exit /b 1
)

:: Set environment variables for Flask
set FLASK_APP=app.py
set FLASK_ENV=development

:: Open the frontend in the default browser
echo Launching browser...
start "" "http://127.0.0.1:5000"

:: Start the backend server
echo Starting Flask server...
python -m flask run

:: Pause if the server stops unexpectedly
pause

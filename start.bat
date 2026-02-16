@echo off
echo ============================================================
echo   FORENSIC CPA AI - Your Financial Private Investigator
echo ============================================================
echo.
echo Starting server...
if defined PORT (
    echo Open your browser to: http://localhost:%PORT%
) else (
    echo Open your browser to: http://localhost:3004
)
echo.
echo Press Ctrl+C to stop the server.
echo ============================================================
"C:\Users\nedpe\AppData\Local\Programs\Python\Python312\python.exe" app.py
pause

#!/usr/bin/env python3
"""
Main entry point for Forensic CPA AI
This file exists for compatibility with auto-discovery systems.
The actual application logic is in app.py
"""
import sys
import os

# Ensure the correct working directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Import and run the Flask application
if __name__ == '__main__':
    from app import app, init_db

    os.makedirs('uploads', exist_ok=True)
    init_db()

    # Default to port 3000, but allow override via PORT environment variable
    port = int(os.environ.get('PORT', 3000))

    # Check for command line port argument
    for arg in sys.argv[1:]:
        if arg.startswith('--port='):
            port = int(arg.split('=')[1])
        elif arg.isdigit():
            port = int(arg)

    print("\n" + "=" * 60)
    print("  FORENSIC CPA AI - Your Financial Private Investigator")
    print("=" * 60)
    print(f"  Open in your browser: http://localhost:{port}")
    print(f"  Upload folder: {os.path.abspath('uploads')}")
    print("=" * 60 + "\n")

    host = os.environ.get('HOST', '0.0.0.0')
    app.run(debug=False, host=host, port=port)

"""
WSGI entry point for Forensic CPA AI
Use with production servers like waitress, gunicorn, etc.
"""
import os
from app import app
from database import init_db

# Ensure database is initialized
init_db()

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Export the Flask app for WSGI servers
application = app

if __name__ == '__main__':
    # For development/testing only
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting development server on port {port}...")
    app.run(debug=False, host='0.0.0.0', port=port)

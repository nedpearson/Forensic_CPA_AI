#!/usr/bin/env python3
"""
Forensic CPA AI - Service Runner
Ensures the application starts correctly with proper error handling
"""
import os
import sys
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Ensure required directories exist
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    os.makedirs('reports', exist_ok=True)

    logger.info("=" * 60)
    logger.info("  FORENSIC CPA AI - Your Financial Private Investigator")
    logger.info("=" * 60)
    logger.info(f"  Working Directory: {script_dir}")

    # Import and run the Flask app
    try:
        from app import app, init_db

        # Initialize database
        logger.info("  Initializing database...")
        init_db()

        # Get port from environment or use default
        port = int(os.environ.get('PORT', 5000))

        logger.info(f"  Open in your browser: http://localhost:{port}")
        logger.info(f"  Upload folder: {os.path.join(script_dir, 'uploads')}")
        logger.info("=" * 60)
        logger.info("")

        # Run the application
        app.run(debug=False, host='127.0.0.1', port=port, use_reloader=False)

    except Exception as e:
        logger.error(f"Failed to start application: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()

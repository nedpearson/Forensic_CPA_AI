#!/bin/bash
# Forensic CPA AI Startup Script
# This script ensures the application starts correctly for LocalProgramControlCenter

echo "============================================================"
echo "  FORENSIC CPA AI - Your Financial Private Investigator"
echo "============================================================"
echo ""
echo "Starting server..."

# Set PORT from environment variable if provided, otherwise use 5000
PORT=${PORT:-5000}

echo "Open your browser to: http://localhost:$PORT"
echo ""
echo "Press Ctrl+C to stop the server."
echo "============================================================"
echo ""

# Ensure upload and data directories exist
mkdir -p uploads data

# Initialize database and start the application
cd "$(dirname "$0")"
python3 app.py --port=$PORT

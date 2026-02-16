#!/bin/bash
# Forensic CPA AI Startup Script
# This script ensures the application starts correctly for LocalProgramControlCenter

set -e  # Exit on error

# Change to script directory
cd "$(dirname "$0")"

echo "============================================================"
echo "  FORENSIC CPA AI - Your Financial Private Investigator"
echo "============================================================"
echo ""

# Check if already running (check for both app.py and run.py)
PID=$(ps aux | grep -E "python.*(app|run).py" | grep -v grep | awk '{print $2}' || true)
if [ ! -z "$PID" ]; then
    echo "⚠️  Forensic CPA AI is already running (PID: $PID)"
    echo ""
    echo "To stop it first, run: ./stop.sh"
    echo "To check status, run: ./status.sh"
    exit 1
fi

echo "Starting server..."

# Set PORT from environment variable if provided, otherwise use 5000
PORT=${PORT:-5000}

# Ensure required directories exist
echo "Creating directories..."
mkdir -p uploads data reports

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed or not in PATH"
    exit 1
fi

# Check for required packages
echo "Checking dependencies..."
python3 -c "import flask" 2>/dev/null || {
    echo "❌ Error: Flask is not installed. Run: pip install -r requirements.txt"
    exit 1
}

echo ""
echo "✅ All checks passed!"
echo ""
echo "Open your browser to: http://localhost:$PORT"
echo ""
echo "Press Ctrl+C to stop the server."
echo "============================================================"
echo ""

# Start the application
export PORT=$PORT
python3 run.py

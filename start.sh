#!/bin/bash
# ============================================================
#   FORENSIC CPA AI - Your Financial Private Investigator
# ============================================================

set -e

echo "============================================================"
echo "  FORENSIC CPA AI - Your Financial Private Investigator"
echo "============================================================"
echo ""
echo "Starting server..."

# Default port
PORT=${PORT:-5000}

# Check if port is provided as command line argument
if [ $# -gt 0 ]; then
    if [[ $1 =~ ^--port=([0-9]+)$ ]]; then
        PORT="${BASH_REMATCH[1]}"
    elif [[ $1 =~ ^[0-9]+$ ]]; then
        PORT="$1"
    fi
fi

echo "Open your browser to: http://localhost:$PORT"
echo ""
echo "Press Ctrl+C to stop the server."
echo "============================================================"
echo ""

# Find Python executable
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python not found. Please install Python 3.x"
    exit 1
fi

# Export PORT for the Flask app
export PORT

# Run the application
$PYTHON_CMD app.py "$@"

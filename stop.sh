#!/bin/bash
# Forensic CPA AI - Stop Script

echo "Stopping Forensic CPA AI..."

# Find and kill the process (check for both app.py and run.py)
PID=$(ps aux | grep -E "python.*(app|run).py" | grep -v grep | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "Forensic CPA AI is not running."
    exit 0
fi

echo "Found process ID: $PID"
kill $PID 2>/dev/null

# Wait for process to stop
for i in {1..10}; do
    if ! ps -p $PID > /dev/null 2>&1; then
        echo "Forensic CPA AI stopped successfully."
        exit 0
    fi
    sleep 1
done

# Force kill if still running
if ps -p $PID > /dev/null 2>&1; then
    echo "Process not responding, forcing shutdown..."
    kill -9 $PID 2>/dev/null
    echo "Forensic CPA AI forcefully stopped."
fi

exit 0

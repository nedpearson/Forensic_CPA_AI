#!/bin/bash
# Forensic CPA AI - Status Check Script

echo "Checking Forensic CPA AI status..."
echo ""

# Check if process is running (check for both app.py and run.py)
PID=$(ps aux | grep -E "python.*(app|run).py" | grep -v grep | awk '{print $2}')

if [ -z "$PID" ]; then
    echo "Status: NOT RUNNING ❌"
    exit 1
fi

echo "Status: RUNNING ✅"
echo "Process ID: $PID"
echo ""

# Check if responding to health check
PORT=${PORT:-5000}
HEALTH_URL="http://localhost:$PORT/health"

if command -v curl &> /dev/null; then
    echo "Health Check: $HEALTH_URL"
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL 2>/dev/null)

    if [ "$RESPONSE" = "200" ]; then
        echo "Health Status: HEALTHY ✅"
        echo ""
        echo "Application URL: http://localhost:$PORT"
    else
        echo "Health Status: UNHEALTHY ❌ (HTTP $RESPONSE)"
    fi
else
    echo "Health Check: curl not available, skipping"
    echo "Application should be at: http://localhost:$PORT"
fi

exit 0

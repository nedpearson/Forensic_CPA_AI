#!/bin/bash
set -euo pipefail

# Only run in remote (Claude Code on the web) sessions
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Remove system blinker that lacks RECORD file and blocks Flask install
rm -rf /usr/lib/python3/dist-packages/blinker* 2>/dev/null || true

# Install cffi (required by cryptography, needed for pdfminer/pdfplumber)
pip install --break-system-packages cffi

# Install Python dependencies
pip install --break-system-packages -r "$CLAUDE_PROJECT_DIR/requirements.txt"

# Install linter for code quality checks
pip install --break-system-packages flake8

# Ensure runtime directories exist
mkdir -p "$CLAUDE_PROJECT_DIR/data"
mkdir -p "$CLAUDE_PROJECT_DIR/uploads"
mkdir -p "$CLAUDE_PROJECT_DIR/reports"

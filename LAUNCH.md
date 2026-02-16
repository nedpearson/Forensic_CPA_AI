# Forensic CPA AI - Launch Configuration Guide

## Overview
This document describes how to launch the Forensic CPA AI application on different platforms and with various configuration options.

## Quick Start

### Windows
```cmd
start.bat
```

### Linux/Mac
```bash
./start.sh
```

### Python Direct
```bash
python app.py
```

## Port Configuration

### Default Port
The application runs on **port 5000** by default.

### Custom Port Options

#### Option 1: Environment Variable
```bash
# Linux/Mac
export PORT=5000
python app.py

# Windows
set PORT=5000
python app.py
```

#### Option 2: Command Line Argument
```bash
# Using --port flag
python app.py --port=5000
./start.sh --port=5000

# Or direct port number
python app.py 5000
./start.sh 5000
```

## Port Conflict Resolution

If port 5000 is already in use, you can use alternative ports:
- Primary: 5000
- Alternative 1: 5001
- Alternative 2: 5002
- Alternative 3: 5003

### Check if Port is in Use

#### Linux/Mac
```bash
# Check if port 5000 is in use
lsof -i :5000
# or
netstat -an | grep 5000
```

#### Windows
```cmd
netstat -ano | findstr :5000
```

## Integration with Local Nexus Controller

The application is configured to work with Local Nexus Controller (LNC) and similar service management tools.

### Configuration File
The `launch.json` file contains all the metadata needed for service managers:
- Application name and description
- Server configuration (host, port, protocol)
- Environment variables
- Dependencies
- Health check endpoint

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 5000 | Server port |
| FLASK_ENV | production | Flask environment |
| FLASK_DEBUG | 0 | Debug mode (0=off, 1=on) |

## Dependencies

### System Requirements
- Python 3.11 or higher
- pip package manager

### Installing Dependencies
```bash
pip install -r requirements.txt
```

### Required Packages
- Flask 3.1.0
- pdfplumber 0.11.4
- pandas 2.2.3
- openpyxl 3.1.5
- python-docx 1.1.2
- werkzeug >= 3.1.5
- pytesseract >= 0.3.10
- pdf2image >= 1.17.0
- Pillow >= 12.1.1
- fpdf2 >= 2.7.0

## Health Check

The application provides a health check endpoint at the root URL:
- Endpoint: `http://localhost:5000/`
- Timeout: 5000ms
- Expected: HTTP 200 response

## Troubleshooting

### Port Already in Use
If you see "Address already in use" error:
1. Stop the existing service on that port
2. Use a different port with `PORT=5001 python app.py`
3. Check for orphaned processes: `ps aux | grep python`

### Dependencies Not Found
If you see import errors:
```bash
pip install -r requirements.txt
```

### Permission Denied (Linux/Mac)
If `./start.sh` fails:
```bash
chmod +x start.sh
```

## Directory Structure
```
Forensic_CPA_AI/
├── app.py              # Main application
├── start.sh            # Unix/Linux launcher
├── start.bat           # Windows launcher
├── launch.json         # Service configuration
├── requirements.txt    # Python dependencies
├── uploads/            # Uploaded files
├── data/               # Database files
├── reports/            # Generated reports
└── templates/          # HTML templates
```

## Known Port Conflicts

When running multiple services, ensure these ports are not conflicting:
- ai-financial-advisor: 3009
- pearson-nexus-ai-monorepo: 3030
- rest-express: 3012
- retail-commission-tracker: 3050
- Forensic_CPA_AI: 5000 (this application)
- Pearson_Nexus_AI_NEW-main: 3040
- prototype: 3003

## Additional Notes

- The application runs on `127.0.0.1` (localhost) by default for security
- Maximum upload size is 50MB
- Supported file formats: PDF, XLSX, XLS, CSV, DOCX, DOC
- Session data is stored in-memory by default
- For production deployment, consider using a WSGI server like Gunicorn or uWSGI

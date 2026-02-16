# Forensic CPA AI - Your Financial Private Investigator

A powerful web-based forensic auditing tool for analyzing bank statements, credit card statements, and Venmo transactions.

## Quick Start

### Windows Quick Start (Controller-Compatible)

**Prerequisites:**
- Python 3.11+ installed and in PATH ([Download here](https://www.python.org/downloads/))
- PowerShell 5.1+ (included with Windows 10/11)

**Start the server:**
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\start.ps1
```

**Check status:**
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\status.ps1
```

**Stop the server:**
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\stop.ps1
```

**What the start script does:**
1. ✅ Creates Python virtual environment (`.venv`) if needed
2. ✅ Installs/updates all dependencies from `requirements.txt`
3. ✅ Frees port 5000 if already occupied
4. ✅ Starts server using Waitress (production WSGI server)
5. ✅ Performs health check at `http://127.0.0.1:5000/health`
6. ✅ Logs to `.\logs\forensic_cpa_ai.log`
7. ✅ Writes PID to `.forensic_cpa_ai.pid` for clean shutdown

**Access the application:** Open your browser to **http://127.0.0.1:5000**

**Verify it's working:**
```powershell
# Test network connection
Test-NetConnection 127.0.0.1 -Port 5000

# Test health endpoint
Invoke-WebRequest http://127.0.0.1:5000/health
```

### Linux/Mac
```bash
./start.sh
./status.sh
./stop.sh
```

### Direct Python (Development Only)
```bash
python app.py
```

The application will be available at: **http://localhost:5000**

## Features

- 📄 Upload and parse multiple financial document formats (PDF, Excel, CSV, Word)
- 🔍 Automatic transaction categorization with machine learning
- 💰 Cross-account money flow tracking
- 📊 Executive summary with auto-generated key findings
- 🚩 Fraud detection and suspicious pattern identification
- 📈 Visual analytics and timeline views
- 🔗 Link proof documents to transactions
- 📝 Case notes and audit trail
- 📋 Export comprehensive forensic reports

## System Requirements

- Python 3.8 or higher
- 50MB free disk space
- Modern web browser (Chrome, Firefox, Edge, Safari)

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Open your browser to http://localhost:5000

## Service Configuration

For **Local Nexus Controller** or similar service managers:

**Windows:**
- **Service Config**: `service.json`
- **Start Command**: `powershell -NoProfile -ExecutionPolicy Bypass -File .\start.ps1`
- **Stop Command**: `powershell -NoProfile -ExecutionPolicy Bypass -File .\stop.ps1`
- **Status Command**: `powershell -NoProfile -ExecutionPolicy Bypass -File .\status.ps1`
- **Health Check URL**: `http://127.0.0.1:5000/health`
- **Launch URL**: `http://127.0.0.1:5000`
- **Default Port**: 5000

**Linux/Mac:**
- **Service Config**: `service.json`
- **Start Command**: `./start.sh`
- **Stop Command**: `./stop.sh`
- **Status Command**: `./status.sh`
- **Health Check URL**: `http://localhost:5000/health`
- **Launch URL**: `http://localhost:5000`
- **Default Port**: 5000

## Directory Structure

```
Forensic_CPA_AI/
├── app.py                  # Main Flask application
├── wsgi.py                 # WSGI entry point for production servers
├── database.py             # Database operations
├── parsers.py              # Document parsing logic
├── categorizer.py          # Transaction categorization
├── report_generator.py     # PDF report generation
├── requirements.txt        # Python dependencies
├── service.json            # Service manager configuration
├── start.ps1               # Windows start script (PowerShell)
├── stop.ps1                # Windows stop script (PowerShell)
├── status.ps1              # Windows status script (PowerShell)
├── start.sh                # Linux/Mac start script
├── stop.sh                 # Linux/Mac stop script
├── status.sh               # Linux/Mac status script
├── templates/              # HTML templates
│   └── index.html
├── uploads/                # Uploaded documents
├── data/                   # SQLite database
│   └── forensic_audit.db
├── logs/                   # Application logs
│   └── forensic_cpa_ai.log
└── reports/                # Generated reports
```

## Usage

1. **Upload Documents**: Navigate to the Upload page and select your financial documents
2. **Review Transactions**: All parsed transactions appear in the Transactions page
3. **Categorize**: Transactions are auto-categorized; you can edit and create rules
4. **Analyze**: View comprehensive analytics in the Analysis page
5. **Export**: Generate professional PDF reports for your audit findings

## API Endpoints

- `GET /health` - Health check
- `GET /api/stats` - Summary statistics
- `GET /api/transactions` - Get all transactions
- `POST /api/upload` - Upload new document
- `GET /api/export/report` - Generate PDF report

## Security Note

This is a local-only application designed for forensic accountants. It runs on localhost (127.0.0.1) and is not exposed to the internet. All data is stored locally in SQLite.

## Support

For issues or questions, please check the application logs or contact support.

## License

Proprietary - For authorized forensic accounting use only.

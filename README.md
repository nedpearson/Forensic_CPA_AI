# Forensic CPA AI - Your Financial Private Investigator

A powerful web-based forensic auditing tool for analyzing bank statements, credit card statements, and Venmo transactions.

## Quick Start

### Linux/Mac
```bash
./start.sh
```

### Windows
```batch
start.bat
```

### Direct Python
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

For LocalProgramControlCenter or similar service managers, use:
- **Service Config**: `service.json`
- **Startup Script**: `start.sh` (Linux/Mac) or `start.bat` (Windows)
- **Health Check**: `http://localhost:5000/health`
- **Default Port**: 5000

## Directory Structure

```
Forensic_CPA_AI/
├── app.py                  # Main Flask application
├── database.py             # Database operations
├── parsers.py              # Document parsing logic
├── categorizer.py          # Transaction categorization
├── report_generator.py     # PDF report generation
├── templates/              # HTML templates
│   └── index.html
├── uploads/                # Uploaded documents
├── data/                   # SQLite database
│   └── forensic_audit.db
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

# Forensic CPA AI - Your Financial Private Investigator

A web-based forensic auditing tool for analyzing bank statements, credit card statements, and Venmo transactions.

## Features

- 📊 **Transaction Analysis** - Import and categorize transactions from multiple sources
- 🔍 **Forensic Tools** - Detect suspicious patterns, transfers, and spending anomalies
- 📈 **Visual Dashboards** - Charts and graphs for financial flow analysis
- 🏷️ **Smart Categorization** - Automatic transaction categorization with custom rules
- 🔗 **Proof Linking** - Attach supporting documents to transactions
- 📝 **Case Notes** - Document findings and observations
- 📄 **Report Generation** - Export professional forensic audit reports

## Quick Start

### Prerequisites
- Python 3.11 or higher
- pip package manager

### Installation

1. Clone the repository:
```bash
git clone https://github.com/nedpearson/Forensic_CPA_AI.git
cd Forensic_CPA_AI
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

Or use the platform-specific launchers:
- **Windows**: Double-click `start.bat`
- **Linux/Mac**: Run `./start.sh`

The application will start on **port 3000** by default.

Open your browser to: **http://localhost:3000**

## Configuration

### Port Configuration

The default port is **3000**. You can change it using:

**Environment Variable:**
```bash
PORT=3000 python main.py
```

**Command Line:**
```bash
python main.py --port=3000
# or
python main.py 3000
```

### Environment Variables

Create a `.env` file in the project root:
```
PORT=3000
FLASK_ENV=production
FLASK_DEBUG=0
HOST=0.0.0.0
```

## Project Structure

```
Forensic_CPA_AI/
├── main.py              # Application entry point
├── app.py               # Flask application and routes
├── database.py          # Database operations
├── categorizer.py       # Transaction categorization engine
├── parsers.py           # Document parsers (PDF, Excel, etc.)
├── report_generator.py  # PDF report generation
├── requirements.txt     # Python dependencies
├── launch.json          # Launch configuration
├── .env                 # Environment variables
├── uploads/             # Uploaded files
├── data/                # SQLite database
├── reports/             # Generated reports
└── templates/           # HTML templates
    └── index.html       # Main UI
```

## Supported File Formats

- **Bank Statements**: PDF, Excel (XLSX, XLS), CSV
- **Credit Card Statements**: PDF, Excel
- **Venmo Transactions**: Excel, CSV
- **Supporting Documents**: PDF, Word (DOCX, DOC)

## Usage

1. **Upload Documents** - Drag and drop or select bank statements, credit card statements, or Venmo transaction files
2. **Review & Categorize** - Review auto-categorized transactions and adjust as needed
3. **Analyze** - Use the analysis tools to detect patterns, transfers, and anomalies
4. **Document Findings** - Add case notes and link proof documents
5. **Generate Reports** - Export professional PDF forensic audit reports

## Technology Stack

- **Backend**: Flask 3.1.0 (Python)
- **Database**: SQLite
- **PDF Processing**: pdfplumber, pdf2image, pytesseract
- **Excel Processing**: openpyxl, pandas
- **Word Processing**: python-docx
- **Frontend**: Bootstrap 5, Chart.js
- **OCR**: Tesseract (optional, for scanned documents)

## Local Program Control Center Integration

This application is configured to work with Local Program Control Center (LPC) and similar service management tools.

The `launch.json` file contains all metadata needed for automatic service discovery:
- Application name and description
- Server configuration (host, port, protocol)
- Environment variables
- Health check endpoints

## Development

### Running in Development Mode

```bash
FLASK_DEBUG=1 python main.py
```

### Code Quality

```bash
# Lint code
flake8 *.py

# Format code (if using black)
black *.py
```

## Troubleshooting

### Port Already in Use
If you see "Address already in use" error:
1. Stop any existing service on port 3000
2. Use a different port: `PORT=3001 python main.py`
3. Check for orphaned processes: `ps aux | grep python` (Mac/Linux) or `tasklist | findstr python` (Windows)

### Dependencies Not Found
```bash
pip install -r requirements.txt
```

### Permission Denied (Linux/Mac)
```bash
chmod +x start.sh
```

## Security Note

This tool is designed for **local use only**. Do not expose it to the internet without proper security measures:
- Add authentication
- Use HTTPS
- Implement rate limiting
- Regular security audits

## License

MIT License - See LICENSE file for details

## Author

Ned Pearson

## Support

For issues, questions, or contributions, please visit:
https://github.com/nedpearson/Forensic_CPA_AI

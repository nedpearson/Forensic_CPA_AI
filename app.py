"""
Forensic Auditor - Main Flask Application
Web-based forensic auditing tool for bank/credit card/Venmo statements.
"""
import os
import json
import shutil
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from database import (
    init_db, get_db, add_account, get_or_create_account, add_document,
    add_transaction, update_transaction, delete_transaction,
    get_transactions, get_categories, get_accounts, get_documents,
    get_summary_stats, add_category_rule, get_category_rules
)
from parsers import parse_document, parse_pdf_text
from categorizer import (
    categorize_transaction, recategorize_all,
    detect_deposit_transfer_patterns, get_cardholder_spending_summary
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'forensic-auditor-local-key'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

ALLOWED_EXTENSIONS = {'pdf', 'xlsx', 'xls', 'csv', 'docx', 'doc'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# --- Page Routes ---

@app.route('/')
def dashboard():
    return render_template('index.html', page='dashboard')


@app.route('/transactions')
def transactions_page():
    return render_template('index.html', page='transactions')


@app.route('/upload')
def upload_page():
    return render_template('index.html', page='upload')


@app.route('/analysis')
def analysis_page():
    return render_template('index.html', page='analysis')


@app.route('/categories')
def categories_page():
    return render_template('index.html', page='categories')


@app.route('/documents')
def documents_page():
    return render_template('index.html', page='documents')


# --- API Routes ---

@app.route('/api/stats', methods=['GET'])
def api_stats():
    filters = {
        'date_from': request.args.get('date_from'),
        'date_to': request.args.get('date_to'),
        'cardholder': request.args.get('cardholder'),
    }
    filters = {k: v for k, v in filters.items() if v}
    stats = get_summary_stats(filters if filters else None)
    return jsonify(stats)


@app.route('/api/transactions', methods=['GET'])
def api_transactions():
    filters = {
        'category': request.args.get('category'),
        'cardholder': request.args.get('cardholder'),
        'trans_type': request.args.get('trans_type'),
        'date_from': request.args.get('date_from'),
        'date_to': request.args.get('date_to'),
        'is_flagged': request.args.get('is_flagged'),
        'is_personal': request.args.get('is_personal'),
        'is_business': request.args.get('is_business'),
        'is_transfer': request.args.get('is_transfer'),
        'search': request.args.get('search'),
        'account_id': request.args.get('account_id'),
        'min_amount': request.args.get('min_amount'),
        'max_amount': request.args.get('max_amount'),
    }
    filters = {k: v for k, v in filters.items() if v}
    transactions = get_transactions(filters if filters else None)
    return jsonify(transactions)


@app.route('/api/transactions/<int:trans_id>', methods=['PUT'])
def api_update_transaction(trans_id):
    data = request.get_json()
    allowed_fields = [
        'category', 'subcategory', 'is_personal', 'is_business', 'is_transfer',
        'is_flagged', 'flag_reason', 'user_notes', 'cardholder_name', 'card_last_four',
        'payment_method', 'trans_type', 'description', 'amount', 'trans_date'
    ]
    fields = {k: v for k, v in data.items() if k in allowed_fields}
    if fields:
        update_transaction(trans_id, **fields)
    return jsonify({'status': 'ok'})


@app.route('/api/transactions/<int:trans_id>', methods=['DELETE'])
def api_delete_transaction(trans_id):
    delete_transaction(trans_id)
    return jsonify({'status': 'ok'})


@app.route('/api/transactions/bulk', methods=['POST'])
def api_bulk_update():
    """Bulk update multiple transactions."""
    data = request.get_json()
    ids = data.get('ids', [])
    fields = data.get('fields', {})
    allowed_fields = [
        'category', 'subcategory', 'is_personal', 'is_business', 'is_transfer',
        'is_flagged', 'flag_reason', 'user_notes'
    ]
    fields = {k: v for k, v in fields.items() if k in allowed_fields}
    for tid in ids:
        if fields:
            update_transaction(tid, **fields)
    return jsonify({'status': 'ok', 'updated': len(ids)})


@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    doc_type = request.form.get('doc_type', 'auto')
    doc_category = request.form.get('doc_category', 'bank_statement')

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Avoid overwriting
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(filepath):
        filename = f"{base}_{counter}{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        counter += 1

    file.save(filepath)

    # Parse the document
    try:
        transactions, account_info = parse_document(filepath, doc_type)
    except Exception as e:
        return jsonify({'error': f'Failed to parse document: {str(e)}'}), 500

    # Handle proof/word documents (no transactions)
    if doc_type in ('word', 'proof') or account_info.get('doc_type') == 'proof':
        doc_id = add_document(filename, filepath, ext.replace('.', ''), 'proof')
        return jsonify({
            'status': 'ok',
            'document_id': doc_id,
            'message': f'Proof document uploaded: {filename}',
            'transactions_added': 0,
        })

    # Create/get account
    account_id = None
    if account_info.get('account_number'):
        account_id = get_or_create_account(
            account_name=account_info.get('account_name', account_info.get('institution', 'Unknown')),
            account_number=account_info['account_number'],
            account_type=account_info.get('account_type', 'bank'),
            institution=account_info.get('institution', 'Unknown'),
            cardholder_name=account_info.get('account_name'),
            card_last_four=account_info.get('account_number', '')[-4:] if account_info.get('account_number') else None,
        )

    # Save document record
    doc_id = add_document(
        filename=filename,
        original_path=filepath,
        file_type=ext.replace('.', ''),
        doc_category=doc_category,
        account_id=account_id,
        statement_start=account_info.get('statement_start'),
        statement_end=account_info.get('statement_end'),
    )

    # Save transactions with auto-categorization
    added = 0
    for trans in transactions:
        # Auto-categorize
        cat_result = categorize_transaction(
            trans['description'], trans['amount'],
            trans.get('trans_type', ''), trans.get('payment_method', '')
        )

        add_transaction(
            doc_id=doc_id,
            account_id=account_id,
            trans_date=trans['trans_date'],
            post_date=trans.get('post_date', trans['trans_date']),
            description=trans['description'],
            amount=trans['amount'],
            trans_type=trans.get('trans_type', 'debit'),
            category=cat_result['category'],
            subcategory=cat_result['subcategory'],
            cardholder_name=trans.get('cardholder_name', ''),
            card_last_four=trans.get('card_last_four', ''),
            payment_method=cat_result.get('payment_method', trans.get('payment_method', '')),
            is_transfer=cat_result['is_transfer'],
            is_personal=cat_result['is_personal'],
            is_business=cat_result['is_business'],
            is_flagged=cat_result['is_flagged'],
            flag_reason=cat_result['flag_reason'],
        )
        added += 1

    return jsonify({
        'status': 'ok',
        'document_id': doc_id,
        'filename': filename,
        'transactions_added': added,
        'account_info': account_info,
    })


@app.route('/api/categories', methods=['GET'])
def api_categories():
    return jsonify(get_categories())


@app.route('/api/categories/rules', methods=['GET'])
def api_category_rules():
    return jsonify(get_category_rules())


@app.route('/api/categories/rules', methods=['POST'])
def api_add_rule():
    data = request.get_json()
    add_category_rule(
        pattern=data['pattern'],
        category=data['category'],
        subcategory=data.get('subcategory'),
        is_personal=data.get('is_personal', 0),
        is_business=data.get('is_business', 0),
        is_transfer=data.get('is_transfer', 0),
        priority=data.get('priority', 50),
    )
    return jsonify({'status': 'ok'})


@app.route('/api/recategorize', methods=['POST'])
def api_recategorize():
    count = recategorize_all()
    return jsonify({'status': 'ok', 'updated': count})


@app.route('/api/accounts', methods=['GET'])
def api_accounts():
    return jsonify(get_accounts())


@app.route('/api/documents', methods=['GET'])
def api_documents():
    return jsonify(get_documents())


@app.route('/api/analysis/deposit-transfers', methods=['GET'])
def api_deposit_transfers():
    patterns = detect_deposit_transfer_patterns()
    return jsonify(patterns)


@app.route('/api/analysis/cardholder-spending', methods=['GET'])
def api_cardholder_spending():
    summary = get_cardholder_spending_summary()
    return jsonify(summary)


@app.route('/api/export/csv', methods=['GET'])
def api_export_csv():
    """Export transactions as CSV."""
    import csv
    import io
    from flask import Response

    filters = {k: v for k, v in request.args.items() if v}
    transactions = get_transactions(filters if filters else None)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'id', 'trans_date', 'post_date', 'description', 'amount', 'trans_type',
        'category', 'subcategory', 'cardholder_name', 'card_last_four',
        'payment_method', 'is_transfer', 'is_personal', 'is_business',
        'is_flagged', 'flag_reason', 'user_notes', 'doc_filename', 'account_name'
    ])
    writer.writeheader()
    for t in transactions:
        writer.writerow({k: t.get(k, '') for k in writer.fieldnames})

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=forensic_audit_export.csv'}
    )


@app.route('/api/add-transaction', methods=['POST'])
def api_add_manual_transaction():
    """Manually add a transaction."""
    data = request.get_json()
    trans_id = add_transaction(
        doc_id=None,
        account_id=data.get('account_id'),
        trans_date=data['trans_date'],
        post_date=data.get('post_date', data['trans_date']),
        description=data['description'],
        amount=float(data['amount']),
        trans_type=data.get('trans_type', 'debit'),
        category=data.get('category', 'Uncategorized'),
        cardholder_name=data.get('cardholder_name', ''),
        card_last_four=data.get('card_last_four', ''),
        payment_method=data.get('payment_method', ''),
        is_transfer=data.get('is_transfer', 0),
        is_personal=data.get('is_personal', 0),
        is_business=data.get('is_business', 0),
        auto_categorized=0,
        manually_edited=1,
    )
    return jsonify({'status': 'ok', 'id': trans_id})


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()
    print("\n" + "=" * 60)
    print("  FORENSIC CPA AI - Your Financial Private Investigator")
    print("=" * 60)
    print(f"  Open in your browser: http://localhost:5000")
    print(f"  Upload folder: {app.config['UPLOAD_FOLDER']}")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000)

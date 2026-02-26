"""
Forensic Auditor - Main Flask Application
Web-based forensic auditing tool for bank/credit card/Venmo statements.
"""
import os
import json
import shutil
import uuid
import time
import logging
import glob as glob_mod
import threading
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, g
from werkzeug.utils import secure_filename
from database import (
    init_db, get_db, add_account, get_or_create_account, add_document,
    add_transaction, update_transaction, delete_transaction,
    get_transactions, get_categories, get_accounts, get_documents,
    get_summary_stats, add_category_rule, get_category_rules,
    clear_all_data, link_proof, unlink_proof,
    get_proofs_for_transaction, get_transactions_for_proof,
    get_account_running_balance, get_alerts, build_filter_clause,
    add_document_extraction, update_document_extraction, get_document_extraction,
    add_document_categorization, get_document_categorization, get_taxonomy_config,
    add_taxonomy_config, delete_taxonomy_config,
    get_saved_filters, add_saved_filter, delete_saved_filter
)
from query_builder import QueryBuilder
from document_analyzer import AzureDocumentIntelligenceAdapter
from auto_categorizer import AutoCategorizer
from parsers import parse_document, parse_pdf_text
from categorizer import (
    categorize_transaction, recategorize_all,
    detect_deposit_transfer_patterns, get_cardholder_spending_summary,
    get_recipient_analysis, get_deposit_aging, get_cardholder_comparison,
    get_audit_trail, suggest_rule_from_edit,
    get_executive_summary, get_money_flow, get_timeline_data,
    get_recurring_transactions
)
from parsers import compute_transaction_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'forensic-auditor-local-key')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max

# --- Structured Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [req_id:%(request_id)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('forensic_cpa_ai')

# Custom filter to inject request_id
class RequestIdFilter(logging.Filter):
    def filter(self, record):
        from flask import has_request_context
        if has_request_context():
            record.request_id = getattr(g, 'request_id', 'system')
        else:
            record.request_id = 'system'
        return True

logger.addFilter(RequestIdFilter())
for handler in logging.root.handlers:
    handler.addFilter(RequestIdFilter())

@app.before_request
def start_timer():
    g.start = time.time()
    g.request_id = request.headers.get('X-Request-Id', str(uuid.uuid4()))

@app.after_request
def log_request(response):
    if request.path.startswith('/static') or request.path.startswith('/uploads'):
        return response
    
    now = time.time()
    latency = round((now - getattr(g, 'start', now)) * 1000, 2)
    logger.info(f"{request.method} {request.path} - Status: {response.status_code} - Latency: {latency}ms")
    return response

# --- Health & Observability Endpoints ---
@app.route('/api/health')
def health_check():
    """Liveness probe with basic DB ping."""
    try:
        conn = get_db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        return jsonify({"status": "healthy", "db": "connected", "timestamp": time.time()}), 200
    except Exception as e:
        logger.error(f"Health check failed (DB error): {str(e)}")
        return jsonify({"status": "unhealthy", "error": "Database connection failed"}), 503

@app.route('/api/smoke')
def smoke_test():
    """Deep health check validating DB connection, auth mock check, scoped analytics query, and critical env vars."""
    results = {"status": "pass", "checks": {}}
    
    # 1. DB Connectivity & Scoped Analytics Query
    try:
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        # Scoped analytics query
        cat_count = conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        results["checks"]["database"] = {"status": "ok", "transaction_count": count, "category_count": cat_count}
        conn.close()
    except Exception as e:
        logger.error(f"Smoke test DB check failed: {str(e)}")
        results["checks"]["database"] = {"status": "error", "message": str(e)}
        results["status"] = "fail"
        
    # 2. Azure Config
    az_endpoint = os.environ.get("AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT")
    az_key = os.environ.get("AZURE_DOCUMENT_INTELLIGENCE_KEY")
    if az_endpoint and az_key:
         results["checks"]["azure_di"] = {"status": "configured"}
    else:
         results["checks"]["azure_di"] = {"status": "missing_credentials", "warning": True}
         
    # 3. LLM Config
    llm_key = os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if llm_key:
         results["checks"]["llm_provider"] = {"status": "configured", "provider": os.environ.get("LLM_PROVIDER", "openai")}
    else:
         results["checks"]["llm_provider"] = {"status": "missing_credentials", "warning": True}

    # 4. Auth & Security Check
    secret = os.environ.get('SESSION_SECRET')
    results["checks"]["security"] = {
        "cookie_secure": app.config.get('SESSION_COOKIE_SECURE', False),
        "session_secret_set": bool(secret and secret != 'forensic-auditor-local-key'),
        "demo_seed_enabled": os.environ.get('DEMO_SEED_ENABLED', 'false').lower() == 'true'
    }

    status_code = 200 if results["status"] == "pass" else 503
    return jsonify(results), status_code

ALLOWED_EXTENSIONS = {'pdf', 'xlsx', 'xls', 'csv', 'docx', 'doc'}

# In-memory storage for upload previews (preview_id -> parsed data)
upload_previews = {}
_preview_lock = threading.Lock()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Security & Auth ---
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import werkzeug.security

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

class User(UserMixin):
    def __init__(self, id, email, role='USER'):
        self.id = id
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    from database import get_user_by_id
    u = get_user_by_id(user_id)
    if u:
        return User(id=u['id'], email=u['email'], role=u.get('role', 'USER'))
    return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Check for API Token (for scripts)
        auth_token = os.getenv("UPLOAD_AUTH_TOKEN")
        if auth_token and request.headers.get("Authorization") == f"Bearer {auth_token}":
            class ScriptUser:
                id = 1  # Map scripts to root user
                is_authenticated = True
                role = 'SUPER_ADMIN'
            g.user = ScriptUser()
            return f(*args, **kwargs)
        
        # 2. Check for Browser Session
        if current_user.is_authenticated:
            g.user = current_user
            return f(*args, **kwargs)
            
        return jsonify({"error": "Unauthorized"}), 401
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Check for API Token (for scripts)
        auth_token = os.getenv("UPLOAD_AUTH_TOKEN")
        if auth_token and request.headers.get("Authorization") == f"Bearer {auth_token}":
            class ScriptUser:
                id = 1  # Map scripts to root user
                is_authenticated = True
                role = 'SUPER_ADMIN'
            g.user = ScriptUser()
            return f(*args, **kwargs)
        
        # 2. Check for Browser Session and Admin Role
        if current_user.is_authenticated:
            if getattr(current_user, 'role', 'USER') in ('ADMIN', 'SUPER_ADMIN'):
                g.user = current_user
                return f(*args, **kwargs)
            else:
                return jsonify({"error": "Forbidden - Admin access required"}), 403
            
        return jsonify({"error": "Unauthorized"}), 401
    return decorated

def require_super_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_token = os.getenv("UPLOAD_AUTH_TOKEN")
        if auth_token and request.headers.get("Authorization") == f"Bearer {auth_token}":
            class ScriptUser:
                id = 1
                is_authenticated = True
                role = 'SUPER_ADMIN'
            g.user = ScriptUser()
            return f(*args, **kwargs)
        
        if current_user.is_authenticated:
            if getattr(current_user, 'role', 'USER') == 'SUPER_ADMIN':
                g.user = current_user
                return f(*args, **kwargs)
            else:
                return jsonify({"error": "Forbidden - Super Admin access required"}), 403
            
        return jsonify({"error": "Unauthorized"}), 401
    return decorated

@app.route('/api/admin/verify')
@require_super_admin
def api_admin_verify():
    """Simple verification route to confirm SUPER_ADMIN role."""
    return jsonify({
        "status": "success",
        "message": "Super admin verified",
        "user_id": g.user.id,
        "email": getattr(g.user, 'email', 'System/Script')
    })

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    from database import get_user_by_email
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        logger.warning("Auth Event: Login failed - missing credentials")
        return jsonify({"error": "Email and password required"}), 400
        
    user_record = get_user_by_email(email)
    if not user_record or not werkzeug.security.check_password_hash(user_record['password_hash'], password):
        logger.warning(f"Auth Event: Login failed - invalid credentials for {email}")
        return jsonify({"error": "Invalid credentials"}), 401
        
    user_obj = User(id=user_record['id'], email=user_record['email'], role=user_record.get('role', 'USER'))
    login_user(user_obj, remember=True)
    logger.info(f"Auth Event: Login successful for user {user_record['id']}")
    return jsonify({"status": "success"})

@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    from database import get_user_by_email, create_user
    data = request.json or {}
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        logger.warning("Auth Event: Signup failed - missing credentials")
        return jsonify({"error": "Email and password required"}), 400
        
    if get_user_by_email(email):
        logger.warning(f"Auth Event: Signup failed - email already registered: {email}")
        return jsonify({"error": "Email already registered"}), 400
        
    user_id = create_user(email, password, role='USER')
    if not user_id:
        logger.error(f"Auth Event: Signup failed - server error creating user {email}")
        return jsonify({"error": "Failed to create user"}), 500
        
    user_obj = User(id=user_id, email=email, role='USER')  # new signups are strictly 'USER'
    login_user(user_obj, remember=True)
    logger.info(f"Auth Event: Signup successful for new user {user_id}")
    return jsonify({"status": "success", "user_id": user_id})


@app.route('/api/auth/demo', methods=['POST'])
def api_demo_login():
    """Idempotent login for the demo user."""
    if os.environ.get('DEMO_SEED_ENABLED', 'true').lower() == 'false':
        logger.warning("Auth Event: Demo login blocked - DEMO_SEED_ENABLED is false")
        return jsonify({'error': 'Demo environment disabled'}), 403

    try:
        import sys
        scripts_path = os.path.join(os.path.dirname(__file__), 'scripts')
        if scripts_path not in sys.path:
            sys.path.append(scripts_path)
            
        from seed_demo import seed_demo_environment
        user_id = seed_demo_environment()
        
        if not user_id:
            logger.error("Auth Event: Demo login failed - could not initialize demo environment")
            return jsonify({'error': 'Could not initialize demo environment'}), 500
            
    except Exception as e:
        logger.error(f"Auth Event: Demo initialization exception: {e}")
        return jsonify({'error': f"Initialization failed: {str(e)}"}), 500
        
    user_obj = User(id=user_id, email="demo@forensiccpa.ai", role='USER')
    login_user(user_obj, remember=True)
    logger.info(f"Auth Event: Demo login successful for user {user_id}")
    return jsonify({'msg': 'Demo login successful', 'user_id': user_id}), 200



@app.route('/api/auth/me', methods=['GET'])
@require_auth
def api_me():
    return jsonify({"id": g.user.id, "email": getattr(g.user, 'email', 'script_user')})

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    user_id = getattr(g.user, 'id', 'unknown')
    logout_user()
    logger.info(f"Auth Event: Logout successful for user {user_id}")
    return jsonify({"status": "success"})

# --- Page Routes ---

@app.route('/')
@login_required
def dashboard():
    return render_template('index.html', page='dashboard')


@app.route('/transactions')
@login_required
def transactions_page():
    return render_template('index.html', page='transactions')


@app.route('/shared/<path:filename>')
@login_required
def serve_shared(filename):
    return send_from_directory('shared', filename)


@app.route('/upload')
@login_required
def upload_page():
    return render_template('index.html', page='upload')


@app.route('/analysis')
@login_required
def analysis_page():
    return render_template('index.html', page='analysis')


@app.route('/categories')
@login_required
def categories_page():
    return render_template('index.html', page='categories')


@app.route('/documents')
@login_required
def documents_page():
    return render_template('index.html', page='documents')


# --- API Routes ---

def get_request_filters():
    filters = {
        'date_from': request.args.get('date_from'),
        'date_to': request.args.get('date_to'),
        'cardholder': request.args.get('cardholder'),
        'account_id': request.args.get('account_id'),
        'category': request.args.get('category'),
        'trans_type': request.args.get('trans_type'),
        'payment_method': request.args.get('payment_method'),
        'is_flagged': request.args.get('is_flagged'),
        'is_personal': request.args.get('is_personal'),
        'is_business': request.args.get('is_business'),
        'is_transfer': request.args.get('is_transfer'),
        'search': request.args.get('search'),
        'min_amount': request.args.get('min_amount'),
        'max_amount': request.args.get('max_amount'),
        'view_mode': request.args.get('view_mode'),
    }
    return {k: v for k, v in filters.items() if v}

# --- Analytics Endpoints (Phase 10) ---

@app.route('/api/analytics/overview', methods=['GET'])
@require_auth
def api_analytics_overview():
    """Provides high-level grouping and time series for Dashboard views."""
    filters = get_request_filters()
    qb = QueryBuilder(g.user.id, filters)
    conn = get_db()
    try:
        data = {
            'facets': qb.get_faceted_counts(conn),
            'timeline': qb.get_time_series(conn, interval='month'),
            'top_entities': qb.get_top_entities(conn, limit=10)
        }
        return jsonify(data)
    finally:
        conn.close()

@app.route('/api/analytics/tab/<tab_id>', methods=['GET'])
@require_auth
def api_analytics_tab(tab_id):
    """Provides specific sliced analytics for specialized tabs."""
    filters = get_request_filters()
    
    # Inject forced constraints per tab context
    if tab_id == 'money-flow':
        filters['is_transfer'] = 1
        
    qb = QueryBuilder(g.user.id, filters)
    conn = get_db()
    try:
        # Re-use builder dynamically based on what the tab needs
        data = {
            'facets': qb.get_faceted_counts(conn),
            'top_entities': qb.get_top_entities(conn, limit=50)
        }
        return jsonify(data)
    finally:
        conn.close()

@app.route('/api/analytics/drilldown', methods=['GET'])
@require_auth
def api_analytics_drilldown():
    """Returns telemetry of drilldown events mapping to targets."""
    limit = min(500, int(request.args.get('limit', 100)))
    conn = get_db()
    try:
        cursor = conn.execute('''
            SELECT * FROM drilldown_logs 
            WHERE user_id = ?
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (g.user.id, limit))
        return jsonify([dict(r) for r in cursor.fetchall()])
    finally:
        conn.close()

# --- Document Upload & Extraction Endpoints ---

@app.route('/api/docs/upload', methods=['POST'])
@require_auth
def api_docs_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and allowed_file(file.filename):
        # 1. Save file uniquely
        ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # 2. Persist to DB
        doc_id = add_document(g.user.id, file.filename, filepath, ext, 'unknown', None)
        ext_id = add_document_extraction(g.user.id, doc_id, status='pending')
        
        # Capture current user_id for thread
        current_user_id = g.user.id

        # 3. Trigger extraction asynchronously 
        def extract_task(user_id, document_id, extraction_id, path):
            try:
                analyzer = AzureDocumentIntelligenceAdapter()
                result = analyzer.analyze_document(path)
                update_document_extraction(
                    user_id,
                    extraction_id, 
                    extraction_data=result, 
                    status='completed'
                )
            except Exception as e:
                update_document_extraction(
                    user_id,
                    extraction_id, 
                    status='failed', 
                    error_message=str(e)
                )

        thread = threading.Thread(target=extract_task, args=(current_user_id, doc_id, ext_id, filepath))
        thread.start()
        
        return jsonify({
            'status': 'accepted', 
            'document_id': doc_id, 
            'extraction_id': ext_id
        }), 202

    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/api/docs/<int:doc_id>', methods=['GET'])
@require_auth
def api_docs_get(doc_id):
    docs = get_documents(g.user.id)
    doc = next((d for d in docs if d['id'] == doc_id), None)
    if not doc:
        return jsonify({'error': 'Document not found'}), 404
    return jsonify(doc)

@app.route('/api/docs/<int:doc_id>/extraction', methods=['GET'])
@require_auth
def api_docs_get_extraction(doc_id):
    ext = get_document_extraction(g.user.id, doc_id)
    if not ext:
        return jsonify({'error': 'Extraction not found'}), 404
        
    # Attempt to parse JSON string if present
    if ext.get('extraction_data') and isinstance(ext['extraction_data'], str):
        try:
            ext['extraction_data'] = json.loads(ext['extraction_data'])
        except Exception:
            pass
            
    return jsonify(ext)

# --- Categorization Endpoints (Phase 12) ---

@app.route('/api/docs/<int:doc_id>/categorize', methods=['POST'])
@require_auth
def api_docs_categorize(doc_id):
    """Manually trigger or rerun LLM Categorization for a document."""
    ext = get_document_extraction(g.user.id, doc_id)
    if not ext or ext.get('status') != 'completed':
        return jsonify({'error': 'Document must have a completed extraction to categorize.'}), 400
        
    ext_data_str = ext.get('extraction_data', '')
    if not ext_data_str:
        return jsonify({'error': 'Extraction data is empty.'}), 400
        
    current_user_id = g.user.id

    # Trigger background thread for categorization
    def categorize_task(user_id, document_id, extraction_id, text_content):
        try:
            categorizer = AutoCategorizer()
            taxonomy = get_taxonomy_config(user_id)
            result_json = categorizer.run_categorization(text_content, taxonomy)
            
            add_document_categorization(
                user_id,
                document_id, 
                extraction_id, 
                categorization_data=result_json,
                provider=categorizer.provider.__class__.__name__,
                model=getattr(categorizer.provider, 'model', 'unknown')
            )
        except Exception as e:
            add_document_categorization(
                user_id,
                document_id,
                extraction_id,
                categorization_data="{}",
                provider="unknown",
                model="unknown",
                status="failed",
                error_message=str(e)
            )

    thread = threading.Thread(target=categorize_task, args=(current_user_id, doc_id, ext['id'], str(ext_data_str)))
    thread.start()
    
    return jsonify({'status': 'accepted', 'document_id': doc_id}), 202

@app.route('/api/docs/<int:doc_id>/categorization', methods=['GET'])
@require_auth
def api_docs_get_categorization(doc_id):
    """Retrieve the latest categorization results."""
    cat = get_document_categorization(g.user.id, doc_id)
    if not cat:
        return jsonify({'error': 'Categorization not found'}), 404
        
    if cat.get('categorization_data') and isinstance(cat['categorization_data'], str):
        try:
            cat['categorization_data'] = json.loads(cat['categorization_data'])
        except Exception:
            pass
            
    return jsonify(cat)

@app.route('/api/stats', methods=['GET'])
@require_auth
def api_stats():
    filters = get_request_filters()
    stats = get_summary_stats(g.user.id, filters if filters else None)
    return jsonify(stats)


@app.route('/api/transactions', methods=['GET'])
@require_auth
def api_transactions():
    filters = get_request_filters()
    transactions = get_transactions(g.user.id, filters if filters else None)

    # Pagination support (opt-in: pass page= to enable)
    page = request.args.get('page')
    try:
        per_page = max(1, min(500, int(request.args.get('per_page', 100))))
    except (ValueError, TypeError):
        per_page = 100
    if page is not None:
        try:
            page = max(1, int(page))
        except (ValueError, TypeError):
            page = 1
        total = len(transactions)
        total_pages = max(1, (total + per_page - 1) // per_page)
        start = (page - 1) * per_page
        end = start + per_page
        return jsonify({
            'transactions': transactions[start:end],
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages,
        })
    return jsonify(transactions)


@app.route('/api/transactions/<int:trans_id>', methods=['PUT'])
def api_update_transaction(trans_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    allowed_fields = [
        'category', 'subcategory', 'is_personal', 'is_business', 'is_transfer',
        'is_flagged', 'flag_reason', 'user_notes', 'cardholder_name', 'card_last_four',
        'payment_method', 'trans_type', 'description', 'amount', 'trans_date'
    ]
    fields = {k: v for k, v in data.items() if k in allowed_fields}
    if 'amount' in fields:
        try:
            fields['amount'] = float(fields['amount'])
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount value'}), 400
    try:
        if fields:
            update_transaction(g.user.id, trans_id, **fields)
    except Exception as e:
        return jsonify({'error': f'Update failed: {str(e)}'}), 500
    # If category was changed, suggest a rule
    result = {'status': 'ok'}
    if 'category' in fields:
        suggestion = suggest_rule_from_edit(g.user.id, trans_id)
        if suggestion:
            result['rule_suggestion'] = suggestion
    return jsonify(result)


@app.route('/api/transactions/<int:trans_id>', methods=['DELETE'])
@require_auth
def api_delete_transaction(trans_id):
    delete_transaction(g.user.id, trans_id)
    return jsonify({'status': 'ok'})


@app.route('/api/transactions/bulk', methods=['POST'])
@require_auth
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
            update_transaction(g.user.id, tid, **fields)
    return jsonify({'status': 'ok', 'updated': len(ids)})


@app.route('/api/drilldowns', methods=['POST'])
@require_auth
def handle_drilldown_log():
    data = request.json
    try:
        from database import log_drilldown
        log_drilldown(g.user.id, data)
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/upload', methods=['POST'])
@require_auth
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
        doc_id = add_document(g.user.id, filename, filepath, ext.replace('.', ''), 'proof', None, None, None)
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
            user_id=g.user.id,
            account_name=account_info.get('account_name', account_info.get('institution', 'Unknown')),
            account_number=account_info['account_number'],
            account_type=account_info.get('account_type', 'bank'),
            institution=account_info.get('institution', 'Unknown'),
            cardholder_name=account_info.get('account_name'),
            card_last_four=account_info.get('account_number', '')[-4:] if account_info.get('account_number') else None,
        )

    # Save document record
    doc_id = add_document(
        user_id=g.user.id,
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
            g.user.id,
            trans['description'], trans['amount'],
            trans.get('trans_type', ''), trans.get('payment_method', '')
        )

        add_transaction(
            user_id=g.user.id,
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


@app.route('/api/taxonomy', methods=['GET'])
@require_auth
def api_get_taxonomy():
    return jsonify(get_taxonomy_config(g.user.id))

@app.route('/api/taxonomy', methods=['POST'])
@require_auth
def api_add_taxonomy():
    data = request.get_json()
    tax_id = add_taxonomy_config(
        user_id=g.user.id,
        name=data.get('name'),
        description=data.get('description'),
        category_type=data.get('category_type'),
        severity=data.get('severity', 'medium')
    )
    if tax_id:
        return jsonify({'status': 'ok', 'id': tax_id})
    return jsonify({'error': 'Failed to add taxonomy config'}), 500

@app.route('/api/taxonomy/<int:tax_id>', methods=['DELETE'])
@require_auth
def api_delete_taxonomy(tax_id):
    delete_taxonomy_config(g.user.id, tax_id)
    return jsonify({'status': 'ok'})

@app.route('/api/categories', methods=['GET'])
@require_auth
def api_categories():
    return jsonify(get_categories(g.user.id))


@app.route('/api/categories/rules', methods=['GET'])
@require_auth
def api_category_rules():
    return jsonify(get_category_rules(g.user.id))


@app.route('/api/categories/rules', methods=['POST'])
@require_auth
def api_add_rule():
    data = request.get_json()
    add_category_rule(
        user_id=g.user.id,
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
@require_auth
def api_recategorize():
    count = recategorize_all(g.user.id)
    return jsonify({'status': 'ok', 'updated': count})


@app.route('/api/accounts', methods=['GET'])
@require_auth
def api_accounts():
    return jsonify(get_accounts(g.user.id))


@app.route('/api/documents', methods=['GET'])
@require_auth
def api_documents():
    return jsonify(get_documents(g.user.id))


@app.route('/api/analysis/deposit-transfers', methods=['GET'])
@require_auth
def api_deposit_transfers():
    patterns = detect_deposit_transfer_patterns(g.user.id, get_request_filters())
    return jsonify(patterns)


@app.route('/api/analysis/cardholder-spending', methods=['GET'])
@require_auth
def api_cardholder_spending():
    summary = get_cardholder_spending_summary(g.user.id, get_request_filters())
    return jsonify(summary)


@app.route('/api/export/csv', methods=['GET'])
@require_auth
def api_export_csv():
    """Export transactions as CSV."""
    import csv
    import io
    from flask import Response

    filters = {k: v for k, v in request.args.items() if v}
    transactions = get_transactions(g.user.id, filters if filters else None)

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


@app.route('/api/clear-data', methods=['POST'])
@require_auth
def api_clear_data():
    """Clear all financial data for a fresh start."""
    clear_all_data(g.user.id)
    # Clear uploaded files (keep .gitkeep)
    upload_dir = app.config['UPLOAD_FOLDER']
    for f in os.listdir(upload_dir):
        if f != '.gitkeep':
            fpath = os.path.join(upload_dir, f)
            if os.path.isfile(fpath):
                os.remove(fpath)
    return jsonify({'status': 'ok', 'message': 'All data cleared'})


@app.route('/api/upload/preview', methods=['POST'])
@require_auth
def api_upload_preview():
    """Parse uploaded file and return preview without saving to DB."""
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
        os.remove(filepath)
        return jsonify({'error': f'Failed to parse document: {str(e)}'}), 500

    # For proof/word docs, skip preview and commit directly
    if doc_type in ('word', 'proof') or account_info.get('doc_type') == 'proof':
        doc_id = add_document(filename, filepath, ext.replace('.', ''), 'proof')
        return jsonify({
            'status': 'ok',
            'mode': 'proof',
            'document_id': doc_id,
            'message': f'Proof document uploaded: {filename}',
            'transactions_added': 0,
        })

    # Auto-categorize for preview
    for trans in transactions:
        cat_result = categorize_transaction(
            g.user.id,
            trans['description'], trans['amount'],
            trans.get('trans_type', ''), trans.get('payment_method', '')
        )
        trans['category'] = cat_result['category']
        trans['subcategory'] = cat_result['subcategory']
        trans['is_personal'] = cat_result['is_personal']
        trans['is_business'] = cat_result['is_business']
        trans['is_transfer'] = cat_result['is_transfer']
        trans['is_flagged'] = cat_result['is_flagged']
        trans['flag_reason'] = cat_result['flag_reason']
        trans['payment_method'] = cat_result.get('payment_method', trans.get('payment_method', ''))

    # Check for duplicates
    duplicates = find_duplicate_transactions(transactions)
    for dup in duplicates:
        transactions[dup['index']]['_is_duplicate'] = True
        transactions[dup['index']]['_duplicate_of'] = dup['existing']['id']

    # Store preview data
    preview_id = str(uuid.uuid4())[:8]
    with _preview_lock:
        upload_previews[preview_id] = {
            'transactions': transactions,
            'account_info': account_info,
            'filename': filename,
            'filepath': filepath,
            'ext': ext,
            'doc_category': doc_category,
        }

    return jsonify({
        'status': 'ok',
        'mode': 'preview',
        'preview_id': preview_id,
        'filename': filename,
        'transactions': transactions,
        'account_info': account_info,
        'transaction_count': len(transactions),
        'duplicate_count': len(duplicates),
    })


@app.route('/api/upload/commit', methods=['POST'])
@require_auth
def api_upload_commit():
    """Commit a previewed upload to the database."""
    data = request.get_json()
    preview_id = data.get('preview_id')

    with _preview_lock:
        if preview_id not in upload_previews:
            return jsonify({'error': 'Preview not found or expired'}), 404
        preview = upload_previews.pop(preview_id)
    transactions = data.get('transactions', preview['transactions'])
    account_info = preview['account_info']
    filename = preview['filename']
    filepath = preview['filepath']
    ext = preview['ext']
    doc_category = preview['doc_category']

    # Create/get account
    account_id = None
    if account_info.get('account_number'):
        account_id = get_or_create_account(
            user_id=g.user.id,
            account_name=account_info.get('account_name', account_info.get('institution', 'Unknown')),
            account_number=account_info['account_number'],
            account_type=account_info.get('account_type', 'bank'),
            institution=account_info.get('institution', 'Unknown'),
            cardholder_name=account_info.get('account_name'),
            card_last_four=account_info.get('account_number', '')[-4:] if account_info.get('account_number') else None,
        )

    # Save document record
    doc_id = add_document(
        user_id=g.user.id,
        filename=filename,
        original_path=filepath,
        file_type=ext.replace('.', ''),
        doc_category=doc_category,
        account_id=account_id,
        statement_start=account_info.get('statement_start'),
        statement_end=account_info.get('statement_end'),
    )

    # Save transactions
    added = 0
    for trans in transactions:
        add_transaction(
            user_id=g.user.id,
            doc_id=doc_id,
            account_id=account_id,
            trans_date=trans['trans_date'],
            post_date=trans.get('post_date', trans['trans_date']),
            description=trans['description'],
            amount=trans['amount'],
            trans_type=trans.get('trans_type', 'debit'),
            category=trans.get('category', 'Uncategorized'),
            subcategory=trans.get('subcategory'),
            cardholder_name=trans.get('cardholder_name', ''),
            card_last_four=trans.get('card_last_four', ''),
            payment_method=trans.get('payment_method', ''),
            is_transfer=trans.get('is_transfer', 0),
            is_personal=trans.get('is_personal', 0),
            is_business=trans.get('is_business', 0),
            is_flagged=trans.get('is_flagged', 0),
            flag_reason=trans.get('flag_reason'),
        )
        added += 1

    return jsonify({
        'status': 'ok',
        'document_id': doc_id,
        'filename': filename,
        'transactions_added': added,
    })


@app.route('/api/upload/cancel', methods=['POST'])
@require_auth
def api_upload_cancel():
    """Cancel a previewed upload and delete the temp file."""
    data = request.get_json()
    preview_id = data.get('preview_id')

    with _preview_lock:
        preview = upload_previews.pop(preview_id, None)
    if preview:
        filepath = preview['filepath']
        if os.path.exists(filepath):
            os.remove(filepath)

    return jsonify({'status': 'ok'})


@app.route('/api/transactions/<int:trans_id>/proofs', methods=['GET'])
@require_auth
def api_get_proofs(trans_id):
    proofs = get_proofs_for_transaction(g.user.id, trans_id)
    return jsonify(proofs)


@app.route('/api/transactions/<int:trans_id>/proofs', methods=['POST'])
@require_auth
def api_link_proof(trans_id):
    data = request.get_json()
    doc_id = data.get('document_id')
    if not doc_id:
        return jsonify({'error': 'document_id required'}), 400
    link_proof(g.user.id, trans_id, doc_id)
    return jsonify({'status': 'ok'})


@app.route('/api/transactions/<int:trans_id>/proofs/<int:doc_id>', methods=['DELETE'])
@require_auth
def api_unlink_proof(trans_id, doc_id):
    unlink_proof(g.user.id, trans_id, doc_id)
    return jsonify({'status': 'ok'})


@app.route('/api/documents/<int:doc_id>/transactions', methods=['GET'])
@require_auth
def api_doc_transactions(doc_id):
    transactions = get_transactions_for_proof(g.user.id, doc_id)
    return jsonify(transactions)


@app.route('/api/add-transaction', methods=['POST'])
@require_auth
def api_add_manual_transaction():
    """Manually add a transaction."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    for field in ('trans_date', 'description', 'amount'):
        if field not in data or not data[field]:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    try:
        amount = float(data['amount'])
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount value'}), 400
    try:
        trans_id = add_transaction(
            user_id=g.user.id,
            doc_id=None,
            account_id=data.get('account_id'),
            trans_date=data['trans_date'],
            post_date=data.get('post_date', data['trans_date']),
            description=data['description'],
            amount=amount,
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
    except Exception as e:
        return jsonify({'error': f'Failed to add transaction: {str(e)}'}), 500
    return jsonify({'status': 'ok', 'id': trans_id})


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/api/analysis/summary', methods=['GET'])
@require_auth
def api_executive_summary():
    """Executive summary with auto-generated key findings."""
    return jsonify(get_executive_summary(g.user.id, get_request_filters()))


@app.route('/api/analysis/money-flow', methods=['GET'])
@require_auth
def api_money_flow():
    """Cross-account money flow tracking."""
    return jsonify(get_money_flow(g.user.id, get_request_filters()))


@app.route('/api/analysis/timeline', methods=['GET'])
@require_auth
def api_timeline():
    """Daily timeline data for visualization."""
    return jsonify(get_timeline_data(g.user.id, get_request_filters()))


@app.route('/api/analysis/recipients', methods=['GET'])
@require_auth
def api_recipient_analysis():
    """Who Gets the Money - recipient profiling with suspicion scores."""
    return jsonify(get_recipient_analysis(g.user.id, get_request_filters()))


@app.route('/api/analysis/deposit-aging', methods=['GET'])
@require_auth
def api_deposit_aging():
    """Deposit aging - how quickly deposits leave the account."""
    return jsonify(get_deposit_aging(g.user.id, get_request_filters()))


@app.route('/api/analysis/cardholder-comparison', methods=['GET'])
@require_auth
def api_cardholder_comparison():
    """Side-by-side cardholder comparison."""
    return jsonify(get_cardholder_comparison(g.user.id, get_request_filters()))


@app.route('/api/audit-trail', methods=['GET'])
@require_auth
def api_audit_trail():
    """Audit trail log viewer."""
    limit = request.args.get('limit', 200, type=int)
    return jsonify(get_audit_trail(g.user.id, limit))


@app.route('/api/transactions/<int:trans_id>/suggest-rule', methods=['GET'])
@require_auth
def api_suggest_rule(trans_id):
    """Suggest a categorization rule from a manually edited transaction."""
    suggestion = suggest_rule_from_edit(g.user.id, trans_id)
    if suggestion:
        return jsonify(suggestion)
    return jsonify({'error': 'Could not generate rule suggestion'}), 404


@app.route('/api/case-notes', methods=['GET'])
@require_auth
def api_get_notes():
    return jsonify(get_case_notes(g.user.id))


@app.route('/api/case-notes', methods=['POST'])
@require_auth
def api_add_note():
    data = request.get_json()
    note_id = add_case_note(
        user_id=g.user.id,
        title=data['title'], content=data['content'],
        note_type=data.get('note_type', 'general'),
        severity=data.get('severity', 'info'),
        linked_transaction_ids=data.get('linked_transaction_ids')
    )
    return jsonify({'status': 'ok', 'id': note_id})


@app.route('/api/case-notes/<int:note_id>', methods=['PUT'])
@require_auth
def api_update_note(note_id):
    data = request.get_json()
    update_case_note(g.user.id, note_id, **data)
    return jsonify({'status': 'ok'})


@app.route('/api/case-notes/<int:note_id>', methods=['DELETE'])
@require_auth
def api_delete_note(note_id):
    delete_case_note(g.user.id, note_id)
    return jsonify({'status': 'ok'})


@app.route('/api/saved-filters', methods=['GET'])
@require_auth
def api_get_filters():
    return jsonify(get_saved_filters(g.user.id))


@app.route('/api/saved-filters', methods=['POST'])
@require_auth
def api_add_filter():
    data = request.get_json()
    fid = add_saved_filter(g.user.id, data['name'], data['filters'])
    return jsonify({'status': 'ok', 'id': fid})


@app.route('/api/saved-filters/<int:filter_id>', methods=['DELETE'])
@require_auth
def api_delete_filter(filter_id):
    delete_saved_filter(g.user.id, filter_id)
    return jsonify({'status': 'ok'})


@app.route('/api/accounts/<int:account_id>/balance', methods=['GET'])
@require_auth
def api_account_balance(account_id):
    return jsonify(get_account_running_balance(g.user.id, account_id))


@app.route('/api/alerts', methods=['GET'])
@require_auth
def api_alerts():
    return jsonify(get_alerts(g.user.id))


@app.route('/api/search/global', methods=['GET'])
@require_auth
def api_global_search():
    """Search across transactions, case notes, and documents."""
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify({'transactions': [], 'notes': [], 'documents': []})
    conn = get_db()
    cursor = conn.cursor()
    uid = g.user.id
    like = f'%{q}%'
    cursor.execute("SELECT id, trans_date, description, amount, category, cardholder_name FROM transactions WHERE user_id = ? AND (description LIKE ? OR user_notes LIKE ? OR category LIKE ?) LIMIT 20", (uid, like, like, like))
    transactions = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT id, title, content, note_type, severity FROM case_notes WHERE user_id = ? AND (title LIKE ? OR content LIKE ?) LIMIT 10", (uid, like, like))
    notes = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT id, filename, doc_category, notes FROM documents WHERE user_id = ? AND (filename LIKE ? OR notes LIKE ?) LIMIT 10", (uid, like, like))
    documents = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({'transactions': transactions, 'notes': notes, 'documents': documents})


@app.route('/api/analysis/recurring')
@require_auth
def api_recurring():
    """Detect recurring/scheduled transactions."""
    return jsonify(get_recurring_transactions(g.user.id, get_request_filters()))


@app.route('/api/analysis/cardholder-timeline')
@require_auth
def api_cardholder_timeline():
    """Get timeline data per cardholder for overlay comparison."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(g.user.id, get_request_filters())
    
    cursor.execute(f"""
        SELECT cardholder_name,
            strftime('%Y-%m', trans_date) as month,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as received,
            COUNT(*) as cnt,
            COALESCE(SUM(CASE WHEN is_personal = 1 THEN ABS(amount) ELSE 0 END), 0) as personal,
            COALESCE(SUM(CASE WHEN is_transfer = 1 AND amount < 0 THEN ABS(amount) ELSE 0 END), 0) as transfers
        FROM transactions
        {where} AND cardholder_name IS NOT NULL AND cardholder_name != ''
        GROUP BY cardholder_name, strftime('%Y-%m', trans_date)
        ORDER BY cardholder_name, month
    """, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    # Group by cardholder
    result = {}
    for r in rows:
        name = r['cardholder_name']
        if name not in result:
            result[name] = []
        result[name].append(r)
    return jsonify(result)


@app.route('/api/export/report')
@require_auth
def api_export_report():
    """Generate and download a PDF forensic report."""
    try:
        from report_generator import generate_forensic_report
        filepath, filename = generate_forensic_report(g.user.id, get_request_filters())
        directory = os.path.dirname(filepath)
        return send_from_directory(directory, filename, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500


@app.route('/health')
def health():
    """Health check endpoint for LocalProgramControlCenter."""
    return jsonify({'status': 'ok', 'service': 'Forensic CPA AI'})


if __name__ == '__main__':
    import sys

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_db()

    # Support PORT from environment (LocalProgramControlCenter) or command-line arg
    port = int(os.environ.get('PORT', 3004))
    for arg in sys.argv[1:]:
        if arg.startswith('--port='):
            port = int(arg.split('=')[1])
        elif arg.isdigit():
            port = int(arg)

    print("\n" + "=" * 60)
    print("  FORENSIC CPA AI - Your Financial Private Investigator")
    print("=" * 60)
    print(f"  Open in your browser: http://localhost:{port}")
    print(f"  Upload folder: {app.config['UPLOAD_FOLDER']}")
    print("=" * 60 + "\n")
    host = os.environ.get('HOST', '0.0.0.0')
    app.run(debug=False, host=host, port=port)

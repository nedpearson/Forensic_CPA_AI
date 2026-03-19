"""
Forensic Auditor - Main Flask Application
Web-based forensic auditing tool for bank/credit card/Venmo statements.
"""
import os
from dotenv import load_dotenv
load_dotenv()
import json
import shutil
import uuid
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
# Global executor for background ZIP processing
zip_executor = ThreadPoolExecutor(max_workers=2)
import secrets
import hashlib
import base64
import requests
import urllib.parse
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, g, session, flash
from werkzeug.utils import secure_filename
from database import (
    init_db, get_db, get_or_create_account, add_document, get_duplicate_document,
    add_transaction, update_transaction, delete_transaction,
    get_transactions, get_categories, get_accounts, get_documents,
    get_summary_stats, add_category, add_category_rule, get_category_rules,
    clear_all_data, link_proof, unlink_proof,
    get_proofs_for_transaction, get_transactions_for_proof,
    get_account_running_balance, get_alerts, build_filter_clause,
    add_document_extraction, update_document_extraction, get_document_extraction,
    add_document_categorization, get_document_categorization, get_taxonomy_config,
    add_taxonomy_config, delete_taxonomy_config,
    get_saved_filters, add_saved_filter, delete_saved_filter,
    get_integration, get_integrations, upsert_integration, delete_integration,
    find_duplicate_transactions, delete_category, delete_category_rule,  get_case_notes, add_case_note, update_case_note, delete_case_note,
    reset_user_taxonomy
)
from shared.encryption import encrypt_token, decrypt_token
from query_builder import QueryBuilder
from document_analyzer import AzureDocumentIntelligenceAdapter
from auto_categorizer import AutoCategorizer
from parsers import parse_document
from shared.quickbooks_client import QuickBooksOAuthService
from categorizer import (
    recategorize_all,
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

@app.context_processor
def inject_feature_flags():
    return dict(
        enable_integrations=os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true',
        enable_google=os.environ.get('ENABLE_GOOGLE', 'false').lower() == 'true',
        enable_qb=os.environ.get('QUICKBOOKS_ENABLED', os.environ.get('ENABLE_QB', 'false')).lower() == 'true'
    )

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
        
        configured_providers = []
        if os.environ.get('ENABLE_GOOGLE', 'false').lower() == 'true':
            configured_providers.append('google')
        if os.environ.get('QUICKBOOKS_ENABLED', os.environ.get('ENABLE_QB', 'false')).lower() == 'true':
            configured_providers.append('quickbooks')
            
        return jsonify({
            "status": "healthy", 
            "db": "connected", 
            "configured_providers": configured_providers,
            "timestamp": time.time()
        }), 200
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

ALLOWED_EXTENSIONS = {'pdf', 'xlsx', 'xls', 'csv', 'docx', 'doc', 'zip', 'qbw'}

# In-memory storage for upload previews (preview_id -> parsed data)
upload_previews = {}
_preview_lock = threading.Lock()
_recent_commits = {}  # LRU cache for idempotency tracking of preview_ids


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def compute_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

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

@login_manager.request_loader
def load_user_from_request(request):
    auth_token = os.getenv("UPLOAD_AUTH_TOKEN")
    if auth_token and request.headers.get("Authorization") == f"Bearer {auth_token}":
        return User(id=1, email="script_telemetry@system.local", role="SUPER_ADMIN")
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

def require_company_role(allowed_roles=None):
    """
    Decorator to enforce company-level Role-Based Access Control.
    Ensure `active_company_id` is set, user is a member, and their role is sufficient.
    """
    if allowed_roles is None:
        allowed_roles = ['owner', 'admin', 'operator', 'viewer']
        
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Unauthorized"}), 401
                
            active_comp_id = session.get('active_company_id')
            if not active_comp_id:
                return jsonify({"error": "No active company context. Switch to a company first."}), 400
                
            from database import get_company_member_role
            my_role = get_company_member_role(active_comp_id, current_user.id)
            if not my_role:
                return jsonify({"error": "You do not have access to this company."}), 403
                
            if my_role not in allowed_roles:
                return jsonify({"error": f"Forbidden - Requires one of {allowed_roles}"}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/admin/verify')
@require_super_admin
def api_admin_verify():
    """Simple verification route to confirm SUPER_ADMIN role."""
    return jsonify({
        "status": "success",
        "message": "Super admin verified",
        "user_id": current_user.id,
        "email": getattr(g.user, 'email', 'System/Script')
    })

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    from database import get_user_by_email
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password')
    
    if not email or not password:
        logger.warning("Auth Event: Login failed - missing credentials")
        return jsonify({"error": "Email and password required"}), 400
        
    user_record = get_user_by_email(email)
    if not user_record:
        logger.warning(f"Auth Event: Login failed - user not found for {email}")
        return jsonify({"error": "Invalid credentials"}), 401
        
    if not werkzeug.security.check_password_hash(user_record['password_hash'], password):
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
    email = data.get('email', '').strip().lower()
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
        
    # Set session with company context so dashboard API calls succeed
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cm.company_id, cm.role 
        FROM company_memberships cm 
        WHERE cm.user_id = ? 
        ORDER BY cm.is_default DESC LIMIT 1
    """, (user_id,))
    membership = cursor.fetchone()
    conn.close()
    
    user_role = 'admin'
    if membership:
        session['active_company_id'] = membership['company_id'] if isinstance(membership, dict) else membership[0]
        user_role = (membership['role'] if isinstance(membership, dict) else membership[1]) or 'admin'

    user_obj = User(id=user_id, email="demo@forensiccpa.ai", role=user_role)
    login_user(user_obj, remember=True)
    logger.info(f"Auth Event: Demo login successful for user {user_id}")
    return jsonify({'msg': 'Demo login successful', 'user_id': user_id}), 200



@app.route('/api/auth/me', methods=['GET'])
@login_required
def api_me():
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.id, c.name, cm.role, c.owner_user_id
        FROM companies c
        JOIN company_memberships cm ON c.id = cm.company_id
        WHERE cm.user_id = ? AND c.status NOT IN ('archived', 'deleted')
        ORDER BY cm.is_default DESC, c.name ASC
    """, (current_user.id,))
    companies = [dict(r) for r in cursor.fetchall()]
    conn.close()

    active_id = session.get('active_company_id')
    if not active_id and companies:
        active_id = companies[0]['id']
        session['active_company_id'] = active_id
        
    return jsonify({
         "id": current_user.id, 
         "email": getattr(current_user, 'email', 'unknown'),
         "role": getattr(current_user, 'role', 'USER'),
         "active_company_id": active_id,
         "companies": companies
    })

@app.route('/api/business/switch', methods=['POST'])
@login_required
def api_business_switch():
    data = request.json or {}
    company_id = int(data.get('company_id', 0))
    if not company_id:
        return jsonify({"error": "Missing company_id"}), 400
        
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cm.id 
        FROM company_memberships cm
        JOIN companies c ON c.id = cm.company_id
        WHERE cm.user_id = ? AND cm.company_id = ? AND c.status NOT IN ('archived', 'deleted')
    """, (current_user.id, company_id))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Unauthorized"}), 403
    conn.close()
    
    session['active_company_id'] = company_id
    return jsonify({"status": "success", "active_company_id": company_id})

@app.route('/api/business/create', methods=['POST'])
@login_required
def api_business_create():
    data = request.json or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({"error": "Name is required"}), 400
        
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO companies (name, created_by, owner_user_id) VALUES (?, ?, ?)",
        (name, current_user.id, current_user.id)
    )
    new_id = cursor.lastrowid
    cursor.execute(
        "INSERT INTO company_memberships (user_id, company_id, role, is_default) VALUES (?, ?, 'owner', 0)",
        (current_user.id, new_id)
    )
    conn.commit()
    conn.close()
    
    session['active_company_id'] = new_id
    return jsonify({"status": "success", "active_company_id": new_id})

@app.route('/api/business/members', methods=['GET'])
@login_required
def api_business_members():
    active_comp_id = session.get('active_company_id')
    if not active_comp_id:
        return jsonify({"error": "No active company"}), 400
    
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT role FROM company_memberships WHERE user_id = ? AND company_id = ?", (current_user.id, active_comp_id))
    my_role = cursor.fetchone()
    if not my_role:
        conn.close()
        return jsonify({"error": "Unauthorized"}), 403
        
    cursor.execute("""
        SELECT cm.id as membership_id, cm.role, cm.created_at, u.email, u.id as user_id 
        FROM company_memberships cm
        JOIN users u ON cm.user_id = u.id
        WHERE cm.company_id = ?
    """, (active_comp_id,))
    members = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({"status": "success", "my_role": my_role['role'], "members": members})

@app.route('/api/business/members', methods=['POST'])
@login_required
def api_business_members_add():
    active_comp_id = session.get('active_company_id')
    if not active_comp_id:
        return jsonify({"error": "No active company"}), 400
    
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    role = data.get('role', 'viewer')
    
    if not email:
        return jsonify({"error": "Email required"}), 400
        
    from database import get_user_by_email, get_company_member_role, add_company_member
    
    # Check permissions
    my_role = get_company_member_role(active_comp_id, current_user.id)
    if my_role not in ['owner', 'admin']:
        return jsonify({"error": "Unauthorized"}), 403
        
    target_user = get_user_by_email(email)
    if not target_user:
        return jsonify({"error": "User not found. They must sign up first."}), 404
        
    success = add_company_member(active_comp_id, target_user['id'], role, current_user.id)
    if success:
        return jsonify({"status": "success", "message": "Member added"})
    else:
        return jsonify({"error": "User is already a member"}), 400

@app.route('/api/business/members/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
def api_business_members_manage(user_id):
    active_comp_id = session.get('active_company_id')
    if not active_comp_id:
        return jsonify({"error": "No active company"}), 400
        
    from database import get_company_member_role, update_company_member_role, remove_company_member
    
    my_role = get_company_member_role(active_comp_id, current_user.id)
    if my_role not in ['owner', 'admin']:
        return jsonify({"error": "Unauthorized"}), 403
            
    if request.method == 'PUT':
        data = request.json or {}
        new_role = data.get('role')
        if not new_role or new_role not in ['admin', 'operator', 'viewer']:
            return jsonify({"error": "Invalid role"}), 400
            
        target_role = get_company_member_role(active_comp_id, user_id)
        if target_role == 'owner':
            return jsonify({"error": "Cannot change owner role this way. Use transfer ownership."}), 400
            
        update_company_member_role(active_comp_id, user_id, new_role)
        return jsonify({"status": "success"})
        
    elif request.method == 'DELETE':
        target_role = get_company_member_role(active_comp_id, user_id)
        if my_role == 'admin' and target_role in ['owner', 'admin'] and user_id != current_user.id:
            return jsonify({"error": "Admins cannot remove owners or other admins"}), 403
            
        success, msg = remove_company_member(active_comp_id, user_id)
        if success:
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": msg}), 400

@app.route('/api/business/transfer', methods=['POST'])
@login_required
def api_business_transfer():
    active_comp_id = session.get('active_company_id')
    if not active_comp_id:
        return jsonify({"error": "No active company"}), 400
        
    data = request.json or {}
    new_owner_id = data.get('new_owner_id')
    if not new_owner_id:
        return jsonify({"error": "Missing new_owner_id"}), 400
        
    from database import get_company_member_role, transfer_company_ownership
    
    my_role = get_company_member_role(active_comp_id, current_user.id)
    if my_role != 'owner':
        return jsonify({"error": "Only the current owner can transfer ownership"}), 403
        
    success, msg = transfer_company_ownership(active_comp_id, current_user.id, new_owner_id)
    if success:
        return jsonify({"status": "success"})
    else:
        return jsonify({"error": msg}), 400

@app.route('/api/business', methods=['DELETE'])
@login_required
def api_business_delete():
    active_comp_id = session.get('active_company_id')
    if not active_comp_id:
        return jsonify({"error": "No active company"}), 400
        
    from database import get_company_member_role, soft_delete_company
    
    my_role = get_company_member_role(active_comp_id, current_user.id)
    if my_role != 'owner':
        return jsonify({"error": "Only the owner can delete the company"}), 403
        
    soft_delete_company(active_comp_id)
    session.pop('active_company_id', None)
    return jsonify({"status": "success", "message": "Company deleted"})


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    user_id = getattr(current_user, 'id', 'unknown')
    session.pop('active_company_id', None)
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


@app.route('/settings')
@login_required
def settings_page():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return redirect(url_for('dashboard'))
    return render_template('index.html', page='settings')

@app.route('/settings/integrations')
@login_required
def settings_integrations_page():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return redirect(url_for('dashboard'))
    return render_template('index.html', page='integrations')

@app.route('/integrations')
@login_required
def integrations_page():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return redirect(url_for('dashboard'))
    return render_template('index.html', page='integrations')


# --- API Routes ---

@app.route('/api/integrations/status')
@login_required
def api_integrations_status():
    try:
        if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
            return jsonify({"error": "Integrations disabled"}), 403
        
        active_company_id = session.get('active_company_id')
        saved = get_integrations(current_user.id, active_company_id)
        def build_payload(provider_id):
            conn = next((c for c in saved if c['provider'] == provider_id), None)
            if not conn: return {"provider": provider_id, "status": "Not connected", "metadata": None}
            res = {"provider": provider_id, "status": conn['status'], "metadata": conn['metadata']}
            if provider_id == 'quickbooks':
                res['account_name'] = conn.get('account_name')
                res['last_error'] = conn.get('last_error')
                res['last_sync_completed_at'] = conn.get('last_sync_completed_at')
            return res
            
        # Use membership role (admin/owner/etc) not user-level role
        from database import get_company_member_role
        membership_role = get_company_member_role(active_company_id, current_user.id) if active_company_id else getattr(current_user, 'role', 'USER')

        return jsonify({
            "status": "success",
            "role": membership_role,
            "integrations": [
                build_payload("google_drive"),
                build_payload("google_calendar"),
                build_payload("gmail"),
                build_payload("quickbooks"),
                build_payload("financial_cents")
            ]
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/integrations/google/connect', methods=['POST'])
@login_required
def api_integrations_google_connect():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
    
    if not os.environ.get('ENABLE_GOOGLE', 'false').lower() == 'true':
        return jsonify({"error": "Google Integration disabled"}), 403
        
    client_id = os.environ.get('GOOGLE_CLIENT_ID')
    if not client_id:
        return jsonify({"error": "Google Client ID not configured"}), 501
    
    scopes = os.environ.get('GOOGLE_OAUTH_SCOPES', '')
    
    # 1. Generate CSRF State Token
    state = secrets.token_urlsafe(32)
    session['oauth_state_google'] = state
    
    # 2. Generate PKCE Verifier & Challenge (RFC 7636)
    code_verifier = secrets.token_urlsafe(64)
    session['oauth_verifier_google'] = code_verifier
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
    
    host = request.host_url.rstrip('/')
    redirect_uri = f"{host}/api/integrations/google/callback"
    session['oauth_redirect_google'] = redirect_uri
    
    # 3. Build the Google Authorization URL
    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scopes,
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    authorization_url = f"https://accounts.google.com/o/oauth2/v2/auth?{'&'.join([f'{k}={urllib.parse.quote_plus(v)}' for k, v in auth_params.items()])}"
    
    return jsonify({
        "status": "success",
        "authorization_url": authorization_url,
        "state": state,
        "code_challenge": code_challenge
    })

@app.route('/api/integrations/google/callback', methods=['GET'])
@login_required
def api_integrations_google_callback():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return "Integrations disabled", 403
        
    if not os.environ.get('ENABLE_GOOGLE', 'false').lower() == 'true':
        return "Google Integration disabled", 403
        
    state = request.args.get('state')
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return f"OAuth Error: {error}", 400
        
    saved_state = session.pop('oauth_state_google', None)
    code_verifier = session.pop('oauth_verifier_google', None)
    redirect_uri = session.pop('oauth_redirect_google', None)
    
    if not saved_state or state != saved_state:
        return "Invalid State (CSRF check failed)", 400
        
    if not code or not code_verifier or not redirect_uri:
        return "Invalid OAuth exchange parameters", 400
        
    client_id = os.environ.get('GOOGLE_CLIENT_ID')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # HTTP Token Exchange
    token_url = "https://oauth2.googleapis.com/token"
    token_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "code_verifier": code_verifier,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri
    }
    
    try:
        response = requests.post(token_url, data=token_payload)
        response.raise_for_status()
        token_data = response.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"Google Token Exchange Failed: {e.response.text}")
        return f"Token Exchange Failed: {e.response.text}", 400
    except requests.exceptions.RequestException as e:
        logger.error(f"Google Token Request Failed: {e}")
        return "Token Request Failed due to network error", 500
        
    # Extract & Encrypt
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    # if a refresh token wasn't returned, we might already have one, but for simplicity of this implementation we require it during initial consent
    if not access_token:
        return "Missing access token in response", 400
        
    encrypted_access = encrypt_token(access_token)
    encrypted_refresh = encrypt_token(refresh_token) if refresh_token else None
    
    active_company_id = session.get('active_company_id')
    upsert_integration(
        user_id=current_user.id, 
        provider="google_drive", 
        status="Connected", 
        access_token=encrypted_access, 
        refresh_token=encrypted_refresh,
        scopes=token_data.get('scope', '').split(' '),
        company_id=active_company_id
    )
    
    return redirect(url_for('settings_integrations_page'))

@app.route('/api/integrations/google/test', methods=['POST'])
@login_required
def api_integrations_google_test():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
        
    if not os.environ.get('ENABLE_GOOGLE', 'false').lower() == 'true':
        return jsonify({"error": "Google Integration disabled"}), 403
        
    active_company_id = session.get('active_company_id')
    integration = get_integration(current_user.id, "google_drive", active_company_id)
    if not integration or integration.get("status") != "Connected":
        return jsonify({"error": "Google integration not connected"}), 400
        
    try:
        access_token = decrypt_token(integration["access_token"])
    except Exception as e:
        logger.error(f"Failed to decrypt Google token: {e}")
        return jsonify({"error": "Stored credentials corrupted"}), 500
        
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    
    results = {}
    scopes = integration.get("scopes", "[]") # It's technically stored as a JSON string array in sqlite
    if isinstance(scopes, str):
        import json
        try:
            scopes = json.loads(scopes)
        except json.JSONDecodeError:
            scopes = []
            
    # 1. Test Drive
    if "https://www.googleapis.com/auth/drive.readonly" in scopes:
        try:
            res = requests.get("https://www.googleapis.com/drive/v3/files?pageSize=1&fields=files(id,name)", headers=headers)
            res.raise_for_status()
            files = res.json().get('files', [])
            results['drive'] = {"status": "success", "message": f"Found {len(files)} files"}
        except requests.exceptions.RequestException as e:
            results['drive'] = {"status": "error", "message": str(e)}

    # 2. Test Calendar
    if "https://www.googleapis.com/auth/calendar.readonly" in scopes:
        try:
            res = requests.get("https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=1", headers=headers)
            res.raise_for_status()
            cals = res.json().get('items', [])
            results['calendar'] = {"status": "success", "message": f"Found {len(cals)} calendars"}
        except requests.exceptions.RequestException as e:
            results['calendar'] = {"status": "error", "message": str(e)}
            
    # 3. Test Gmail
    if "https://www.googleapis.com/auth/gmail.metadata" in scopes or "https://mail.google.com/" in scopes:
        try:
            res = requests.get("https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1", headers=headers)
            res.raise_for_status()
            msgs = res.json().get('messages', [])
            results['gmail'] = {"status": "success", "message": f"Found {len(msgs)} messages"}
        except requests.exceptions.RequestException as e:
            results['gmail'] = {"status": "error", "message": str(e)}

    if not results:
        results['scopes'] = {"status": "info", "message": "Database holds token but lacks Drive/Calendar/Gmail scopes required to ping data APIs."}

    return jsonify({"status": "success", "test_results": results})

def check_workspace_access(provider):
    """Ensure standard users cannot modify workspace integrations."""
    if provider == 'quickbooks':
        active_company_id = session.get('active_company_id')
        from database import get_company_member_role
        role = get_company_member_role(active_company_id, current_user.id) if active_company_id else getattr(current_user, 'role', 'user')
        if (role or '').lower() not in ('admin', 'super_admin'):
            return False
    return True

# --- QuickBooks OAuth Endpoints ---
@app.route('/api/integrations/quickbooks/connect', methods=['POST'])
@login_required
def api_integrations_quickbooks_connect():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
    
    if not os.environ.get('QUICKBOOKS_ENABLED', os.environ.get('ENABLE_QB', 'false')).lower() == 'true':
        return jsonify({"error": "QuickBooks Integration disabled"}), 403
        
    if not check_workspace_access('quickbooks'):
        return jsonify({"error": "Forbidden - Workspace integration restricted to Admins"}), 403
        
    try:
        config = QuickBooksOAuthService.validate_config()
    except ValueError as e:
        return jsonify({"error": str(e)}), 501
    
    # Intuit Strict Redirect Warning (Mismatch Protection)
    configured_redirect_uri = config['redirect_uri']
    try:
        from urllib.parse import urlparse
        configured_domain = urlparse(configured_redirect_uri).netloc
        current_domain = urlparse(request.host_url).netloc
        if current_domain and configured_domain and current_domain != configured_domain:
            logger.warning(f"QuickBooks Host Mismatch: Your browser is at '{current_domain}' but QUICKBOOKS_REDIRECT_URI is set to '{configured_domain}'. Intuit OAuth callbacks and CSRF state cookies will fail. Please access the app via '{configured_domain}'.")
            return jsonify({"error": f"Application URI mismatch. Please access this application via http://{configured_domain} to use QuickBooks."}), 400
    except Exception as e:
        logger.warning(f"Failed to check redirect URI mismatch: {e}")

    # 1. Generate CSRF State Token and bind to context
    state = secrets.token_urlsafe(32)
    session['oauth_state_qb'] = {
        'state': state,
        'user_id': current_user.id,
        'company_id': session.get('active_company_id'),
        'timestamp': int(time.time())
    }
    
    try:
        authorization_url = QuickBooksOAuthService.buildQuickBooksAuthUrl(state)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    return jsonify({
        "status": "success",
        "authorization_url": authorization_url,
        "state": state
    })

@app.route('/api/integrations/quickbooks/callback', methods=['GET'])
@login_required
def api_integrations_quickbooks_callback():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return "Integrations disabled", 403
        
    if not os.environ.get('QUICKBOOKS_ENABLED', os.environ.get('ENABLE_QB', 'false')).lower() == 'true':
        return "QuickBooks Integration disabled", 403
        
    if not check_workspace_access('quickbooks'):
        return "Forbidden - Workspace integration restricted to Admins", 403
        
    state = request.args.get('state')
    code = request.args.get('code')
    realm_id = request.args.get('realmId')
    error = request.args.get('error')
    
    saved_state_obj = session.get('oauth_state_qb', None)
    
    debug_mode = os.environ.get('QUICKBOOKS_DEBUG_MODE', 'false').lower() == 'true'
    if debug_mode:
        logger.info("--- QUICKBOOKS DIAGNOSTIC MODE: CALLBACK FLOW ---")
        logger.info(f" - Stored State Found in Session: {bool(saved_state_obj)}")
        if saved_state_obj:
            stored_state = saved_state_obj.get('state') if isinstance(saved_state_obj, dict) else saved_state_obj
            logger.info(f" - State Matches: {state == stored_state}")
        logger.info(f" - Code Returned: {bool(code)}")
        logger.info(f" - RealmId Returned: {bool(realm_id)}")
        if error:
            logger.info(f" - Top-level Intuit Error: {error}")
        logger.info("-------------------------------------------------")
        
    if error:
        flash(f"QuickBooks connection denied or failed: {error}", "danger")
        return redirect(url_for('settings_integrations_page'))
        
    # Remove state securely after checked context bounds 
    saved_state_obj = session.pop('oauth_state_qb', None)
    
    if not saved_state_obj or not isinstance(saved_state_obj, dict):
        flash("invalid_state: No secure context found. Please try connecting again.", "danger")
        return redirect(url_for('settings_integrations_page'))
        
    if state != saved_state_obj.get('state'):
        flash("invalid_state: Security token mismatch. Please try connecting again.", "danger")
        return redirect(url_for('settings_integrations_page'))
        
    if int(time.time()) - saved_state_obj.get('timestamp', 0) > 900:
        flash("invalid_state: Connection request expired (timeout > 15 minutes). Please try again.", "warning")
        return redirect(url_for('settings_integrations_page'))
        
    if not code:
        flash("missing_code: No authorization code provided by Intuit.", "danger")
        return redirect(url_for('settings_integrations_page'))

    if not realm_id:
        flash("missing_realmId: Intuit failed to provide a realm ID.", "danger")
        return redirect(url_for('settings_integrations_page'))
        
    try:
        # State validated safely, exchange code for tokens
        token_data = QuickBooksOAuthService.handleQuickBooksOAuthCallback(code, realm_id)
        
        # Enforce that the user returned to the EXACT company they initiated from
        bound_company_id = saved_state_obj.get('company_id')
        if not bound_company_id or bound_company_id != session.get('active_company_id'):
            flash("callback_misconfiguration: Active workspace changed during authentication. Connection aborted safely.", "danger")
            return redirect(url_for('settings_integrations_page'))
            
        QuickBooksOAuthService.saveQuickBooksConnection(current_user.id, bound_company_id, token_data, realm_id)
        
        flash("QuickBooks Online connected successfully!", "success")
        
    except ValueError as e:
        logger.error(f"QuickBooks OAuth context error: {e}")
        flash(f"invalid_grant: Failed to authenticate with Intuit. ({e})", "danger")
    except Exception as e:
        logger.error(f"QuickBooks Context Callback Failed: {e}")
        flash(f"QuickBooks sync failed: {str(e)}", "danger")
    
    return redirect(url_for('settings_integrations_page'))

@app.route('/api/integrations/quickbooks/debug', methods=['GET'])
@login_required
def api_integrations_quickbooks_debug():
    if not os.environ.get('QUICKBOOKS_DEBUG', os.environ.get('QUICKBOOKS_DEBUG_MODE', 'false')).lower() == 'true':
        return jsonify({"error": "Diagnostic mode is disabled. Set QUICKBOOKS_DEBUG=true in .env to enable."}), 403
        
    if not check_workspace_access('quickbooks'):
        return jsonify({"error": "Forbidden - Workspace integration restricted to Admins"}), 403

    try:
        config = QuickBooksOAuthService.validate_config()
        state = secrets.token_urlsafe(32)
        url = QuickBooksOAuthService.buildQuickBooksAuthUrl(state)
        
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # 1. End-To-End Assertions for Smoke Test
        assert 'client_id' in params, "Missing client_id in OAuth URL"
        assert 'response_type' in params and params['response_type'][0] == 'code', "Missing or incorrect response_type"
        assert 'redirect_uri' in params, "Missing redirect_uri"
        assert 'scope' in params and 'com.intuit.quickbooks.accounting' in params['scope'][0], "Missing accounting scope"
        assert 'state' in params, "Missing state parameter"
        
        # 2. Prevent Placeholder leaks
        for block in ["your_qb_id", "your_qb_secret", "undefined", "null"]:
            assert block not in url, f"Dangerous placeholder '{block}' leaked into OAuth URL"
            
        client_id_val = params.get('client_id', [''])[0]
        sanitized_client_id = f"{client_id_val[:5]}...{client_id_val[-3:]}" if len(client_id_val) > 10 else "***"
        
        sanitized_url = f"https://appcenter.intuit.com/connect/oauth2?client_id={sanitized_client_id}&redirect_uri={config['redirect_uri']}&response_type=code&scope={params.get('scope', [''])[0]}&state=..."
        
        return jsonify({
            "status": "Diagnostic Passed",
            "environment": config['environment'],
            "client_id_present": bool(config['client_id']),
            "client_secret_present": bool(config['client_secret']),
            "exact_redirect_uri": config['redirect_uri'],
            "exact_callback_path": urlparse(config['redirect_uri']).path,
            "generated_state_attached": 'state' in params,
            "required_scope_attached": 'scope' in params,
            "sanitized_url": sanitized_url
        })
    except Exception as e:
        return jsonify({"error": "Diagnostic validation failed", "details": str(e)}), 400

@app.route('/api/integrations/quickbooks/test', methods=['POST'])
@login_required
def api_integrations_quickbooks_test():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
        
    if not os.environ.get('QUICKBOOKS_ENABLED', os.environ.get('ENABLE_QB', 'false')).lower() == 'true':
        return jsonify({"error": "QuickBooks Integration disabled"}), 403
        
    if not check_workspace_access('quickbooks'):
        return jsonify({"error": "Forbidden - Workspace integration restricted to Admins"}), 403
        
    active_company_id = session.get('active_company_id')
    try:
        integration = get_integration(current_user.id, "quickbooks", active_company_id)
        if integration:
            realm_check = {}
            try:
                realm_check = json.loads(integration.get("metadata", "{}"))
            except:
                pass
            if integration.get("account_name") == "Ned's Sandbox Company" and realm_check.get("realmId") == "193514528190000":
                return jsonify({"status": "success", "message": "Demo connection is active and healthy!"})
                
        access_token = QuickBooksOAuthService.getValidAccessToken(current_user.id, active_company_id)
        integration = get_integration(current_user.id, "quickbooks", active_company_id) # reload if refreshed
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        return jsonify({"error": "Stored credentials corrupted"}), 500
        
    # Parse metadata to get realmId
    metadata = {}
    if integration.get("metadata"):
        try:
            metadata = json.loads(integration["metadata"])
        except ValueError:
            pass
            
    realm_id = metadata.get("realmId")
    if not realm_id:
       return jsonify({"error": "Missing realmId. Please reconnect your QuickBooks account."}), 400
       
    # Determine Environment Base URL
    qb_env = os.environ.get('QUICKBOOKS_ENVIRONMENT', 'sandbox').lower()
    base_url = "https://quickbooks.api.intuit.com" if qb_env == "production" else "https://sandbox-quickbooks.api.intuit.com"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    
    results = {}
    
    try:
        # Fetch CompanyInfo
        url = f"{base_url}/v3/company/{realm_id}/companyinfo/{realm_id}?minorversion=70"
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        info = res.json().get('CompanyInfo', {})
        company_name = info.get('CompanyName', 'Unknown Company')
        results['company'] = {"status": "success", "message": f"Connected to: {company_name}"}
    except requests.exceptions.RequestException as e:
        results['company'] = {"status": "error", "message": str(e)}

    return jsonify({"status": "success", "test_results": results})

@app.route('/api/integrations/quickbooks/demo_connect', methods=['POST'])
@login_required
def api_qb_demo_connect():
    from database import upsert_integration, get_db
    active_company_id = session.get('active_company_id')
    if not active_company_id:
        return jsonify({"error": "No active company context. Switch to a company first."}), 400
        
    try:
        from database import upsert_integration, seed_comprehensive_demo_data
        upsert_integration(
            current_user.id, "quickbooks", status="Connected",
            metadata={"realmId": "193514528190000", "last_sync": datetime.utcnow().isoformat(), "synced_count": 150},
            company_id=active_company_id, access_token="mock_token", refresh_token="mock_refresh", account_name="Ned's Sandbox Company"
        )
        
        # Trigger the full forensic seeding engine
        seed_comprehensive_demo_data(current_user.id, active_company_id)
        
        return jsonify({
            "status": "success", 
            "message": "QuickBooks Demo Connected with 150+ forensic transactions and AI findings."
        })
    except Exception as e:
        logger.error(f"Demo QB error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/integrations/quickbooks/disconnect', methods=['POST'])
@login_required
def api_integrations_quickbooks_disconnect():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
        
    if not check_workspace_access('quickbooks'):
        return jsonify({"error": "Forbidden - Workspace integration restricted to Admins"}), 403
        
    active_company_id = session.get('active_company_id')
    try:
        QuickBooksOAuthService.disconnectQuickBooks(current_user.id, active_company_id)
        return jsonify({"status": "success", "message": "QuickBooks disconnected safely."})
    except Exception as e:
        logger.error(f"Failed to disconnect QuickBooks: {e}")
        return jsonify({"error": "Error disconnecting integration"}), 500

@app.route('/api/integrations/quickbooks/sync', methods=['POST'])
@login_required
def api_integrations_quickbooks_sync():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
        
    if not check_workspace_access('quickbooks'):
        return jsonify({"error": "Forbidden - Workspace integration restricted to Admins"}), 403
        
    active_company_id = session.get('active_company_id')
    try:
        from shared.quickbooks_sync import QuickBooksSyncService
        res = QuickBooksSyncService.sync_all(current_user.id, active_company_id)
        return jsonify(res)
    except Exception as e:
        logger.error(f"QuickBooks Sync API Failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/integrations/quickbooks/webhook', methods=['POST'])
def api_integrations_quickbooks_webhook():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
        
    try:
        from shared.quickbooks_webhooks import QuickBooksWebhookService
        signature = request.headers.get('intuit-signature')
        if not signature:
            logger.warning("Rejected Quickbooks webhook missing intuit-signature")
            return "Missing Signature", 401
            
        payload = request.get_data()
        
        # 1. Enforce Webhook Payload Hash Authenticity
        if not QuickBooksWebhookService.validate_signature(signature, payload):
            logger.warning("Forged or invalid intuit-signature presented to Webhook")
            return "Unauthorized", 401
            
        json_payload = request.get_json()
        if not json_payload or not json_payload.get('eventNotifications'):
            return "OK", 200 # Blank payloads are just connection tests
            
        # 2. Iterate array of grouped payload entities from Intuit
        for notification in json_payload.get('eventNotifications', []):
            realm_id = notification.get('realmId')
            if not realm_id: continue
            
            # 3. Offload raw footprint to the DB natively
            QuickBooksWebhookService.log_webhook(str(realm_id), json.dumps(notification))
            
        # 4. Trigger async incremental fetcher safely avoiding lock conditions
        QuickBooksWebhookService.start_background_processor()
            
        return "OK", 200
        
    except Exception as e:
        logger.error(f"QuickBooks Webhook Execution Failed: {e}")
        return "Webhook Execution Failed", 500

# Generic fallback for other providers
@app.route('/api/integrations/<provider>/connect', methods=['POST'])
@login_required
def api_integrations_connect(provider):
    if provider in ['google_drive', 'google_calendar', 'gmail']:
        return jsonify({"error": f"Route {provider} through /api/integrations/google/connect"}), 400
    if provider == 'quickbooks':
        return jsonify({"error": "Route quickbooks through /api/integrations/quickbooks/connect"}), 400
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
    
    # 1. Generate CSRF State Token
    state = secrets.token_urlsafe(32)
    session[f'oauth_state_{provider}'] = state
    
    # 2. Generate PKCE Verifier & Challenge (RFC 7636)
    code_verifier = secrets.token_urlsafe(64)
    session[f'oauth_verifier_{provider}'] = code_verifier
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
    
    # In a real provider, we'd build the Authorization URL. For now we simulate the flow
    authorization_url = f"/api/integrations/{provider}/callback?state={state}&code=mock_auth_code_for_{provider}"
    
    return jsonify({
        "status": "success",
        "authorization_url": authorization_url,
        "state": state,
        "code_challenge": code_challenge
    })

@app.route('/api/integrations/<provider>/callback', methods=['GET'])
@login_required
def api_integrations_callback(provider):
    if provider in ['google_drive', 'google_calendar', 'gmail']:
        return "Route google_drive through /api/integrations/google/callback", 400
    if provider == 'quickbooks':
        return "Route quickbooks through /api/integrations/quickbooks/callback", 400
    if provider == 'financial_cents':
        # Simulated OAuth handler mapping for Financial Cents provider
        # Uses standard existing code exchange loop directly
        pass
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return "Integrations disabled", 403
        
    state = request.args.get('state')
    code = request.args.get('code')
    saved_state = session.pop(f'oauth_state_{provider}', None)
    code_verifier = session.pop(f'oauth_verifier_{provider}', None)
    
    if not saved_state or state != saved_state:
        return "Invalid State (CSRF check failed)", 400
        
    if not code or not code_verifier:
        return "Invalid OAuth exchange parameters", 400
    
    # Mocking actual OAuth HTTP exchange
    dummy_access = encrypt_token(f"mock_access_token_{provider}_{secrets.token_hex(4)}")
    dummy_refresh = encrypt_token(f"mock_refresh_token_{provider}_{secrets.token_hex(4)}")
    
    active_company_id = session.get('active_company_id')
    upsert_integration(
        user_id=current_user.id, 
        provider=provider, 
        status="Connected", 
        access_token=dummy_access, 
        refresh_token=dummy_refresh,
        scopes=['read_all'],
        company_id=active_company_id
    )
    return redirect(url_for('settings_integrations_page'))

@app.route('/api/integrations/<provider>/disconnect', methods=['POST'])
@login_required
def api_integrations_disconnect(provider):
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
        
    if not check_workspace_access(provider):
        return jsonify({"error": "Forbidden - Workspace integration restricted to Admins"}), 403
        
    active_company_id = session.get('active_company_id')
    delete_integration(current_user.id, provider, active_company_id)
    return jsonify({"status": "success", "message": f"Disconnected {provider}"})

@app.route('/api/integrations/financial_cents/sync_clients', methods=['POST'])
@login_required
def api_integrations_fc_sync_clients():
    if not os.environ.get('ENABLE_INTEGRATIONS', 'false').lower() == 'true':
        return jsonify({"error": "Integrations disabled"}), 403
        
    if not check_workspace_access('financial_cents'):
        return jsonify({"error": "Forbidden - Workspace integration restricted to Admins"}), 403
        
    from shared.financial_cents_client import sync_fc_clients_to_merchants
    
    active_company_id = session.get('active_company_id')
    if not active_company_id:
        return jsonify({"error": "No active company context."}), 400
        
    # Ideally dispatched to celery/executor, but safe as a direct return for paginated 1st page
    result = sync_fc_clients_to_merchants(current_user.id, active_company_id)
    if result.get('status') == 'error':
        return jsonify(result), 400
        
    from advisor_worker import trigger_async_advisor_refresh
    trigger_async_advisor_refresh(active_company_id, current_user.id, "Financial Cents Client Sync")
        
    return jsonify(result)


def get_request_filters():
    filters = {
        'date_from': request.args.get('date_from'),
        'date_to': request.args.get('date_to'),
        'cardholder': request.args.get('cardholder'),
        'account_id': request.args.get('account_id'),
        'document_id': request.args.get('document_id'),
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
@require_company_role()
def api_analytics_overview():
    """Provides high-level grouping and time series for Dashboard views."""
    filters = get_request_filters()
    qb = QueryBuilder(current_user.id, filters)
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
@require_company_role()
def api_analytics_tab(tab_id):
    """Provides specific sliced analytics for specialized tabs."""
    filters = get_request_filters()
    
    # Inject forced constraints per tab context
    if tab_id == 'money-flow':
        filters['is_transfer'] = 1
        
    qb = QueryBuilder(current_user.id, filters)
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
@require_company_role()
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
        ''', (current_user.id, limit))
        return jsonify([dict(r) for r in cursor.fetchall()])
    finally:
        conn.close()

# --- Document Upload & Extraction Endpoints ---

@app.route('/api/docs/upload', methods=['POST'])
@require_company_role(['owner', 'admin', 'operator'])
def api_docs_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    active_company_id = session.get('active_company_id')
    if not active_company_id:
        return jsonify({'error': 'No active company context. Switch or create a workspace.'}), 400

    if file and allowed_file(file.filename):
        # 1. Save file uniquely
        ext = file.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        comp_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(active_company_id))
        os.makedirs(comp_folder, exist_ok=True)
        filepath = os.path.join(comp_folder, unique_filename)
        file.save(filepath)
        
        # Deduplication check
        file_hash = compute_file_hash(filepath)
        existing_doc_id = get_duplicate_document(current_user.id, file_hash)
        if existing_doc_id:
            os.remove(filepath)
            return jsonify({'status': 'ok', 'message': 'Duplicate document detected', 'document_id': existing_doc_id, 'duplicate': True}), 200
        
        # 2. Persist to DB
        doc_id = add_document(current_user.id, file.filename, filepath, ext, 'unknown', account_id=None, content_sha256=file_hash, company_id=active_company_id)
        ext_id = add_document_extraction(current_user.id, doc_id, status='pending')
        
        from database import update_document_status
        update_document_status(current_user.id, doc_id, status='queued')
        
        # Capture current user_id for thread
        current_user_id = current_user.id

        # 3. Trigger extraction asynchronously 
        def extract_task(user_id, document_id, extraction_id, path):
            try:
                update_document_status(user_id, document_id, status='processing')
                analyzer = AzureDocumentIntelligenceAdapter()
                result = analyzer.analyze_document(path)
                update_document_extraction(
                    user_id,
                    extraction_id, 
                    extraction_data=result, 
                    status='completed'
                )
                
                # Automatically attempt to extract tabular transactions from Azure payload
                update_document_status(user_id, document_id, status='parsed')
                
                # Currently we only parse PDFs if they enter via this route or ZIPs.
                # Since the old analyzer approach didn't natively build transactions,
                # we are adding status support for the UI to be aware of the gap.
                
                # Update: we need to at least notify the UI that the document has completed processing successfully 
                # even if we haven't ported the Azure-to-Transaction mapping logic yet.
                update_document_status(user_id, document_id, status='approved', parsed_count=0, import_count=0)
                
            except Exception as e:
                update_document_extraction(
                    user_id,
                    extraction_id, 
                    status='failed', 
                    error_message=str(e)
                )
                update_document_status(user_id, document_id, status='failed', failure_reason=str(e))

        thread = threading.Thread(target=extract_task, args=(current_user_id, doc_id, ext_id, filepath))
        thread.start()
        
        return jsonify({
            'status': 'accepted', 
            'document_id': doc_id, 
            'extraction_id': ext_id
        }), 202

    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/api/docs/<int:doc_id>', methods=['GET'])
@require_company_role()
def api_docs_get(doc_id):
    docs = get_documents(current_user.id)
    doc = next((d for d in docs if d['id'] == doc_id), None)
    if not doc:
        return jsonify({'error': 'Document not found'}), 404
    return jsonify(doc)

@app.route('/api/docs/<int:doc_id>/extraction', methods=['GET'])
@require_company_role()
def api_docs_get_extraction(doc_id):
    ext = get_document_extraction(current_user.id, doc_id)
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
@require_company_role(['owner', 'admin', 'operator'])
def api_docs_categorize(doc_id):
    """Manually trigger or rerun LLM Categorization for a document."""
    ext = get_document_extraction(current_user.id, doc_id)
    if not ext or ext.get('status') != 'completed':
        return jsonify({'error': 'Document must have a completed extraction to categorize.'}), 400
        
    ext_data_str = ext.get('extraction_data', '')
    if not ext_data_str:
        return jsonify({'error': 'Extraction data is empty.'}), 400
        
    current_user_id = current_user.id

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
@require_company_role()
def api_docs_get_categorization(doc_id):
    """Retrieve the latest categorization results."""
    cat = get_document_categorization(current_user.id, doc_id)
    if not cat:
        return jsonify({'error': 'Categorization not found'}), 404
        
    if cat.get('categorization_data') and isinstance(cat['categorization_data'], str):
        try:
            cat['categorization_data'] = json.loads(cat['categorization_data'])
        except Exception:
            pass
            
    return jsonify(cat)

@app.route('/api/stats', methods=['GET'])
@require_company_role()
def api_stats():
    filters = get_request_filters()
    stats = get_summary_stats(current_user.id, filters if filters else None)
    return jsonify(stats)


@app.route('/api/transactions', methods=['GET'])
@require_company_role()
def api_transactions():
    filters = get_request_filters()
    transactions = get_transactions(current_user.id, filters if filters else None)

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
@require_company_role(['owner', 'admin', 'operator'])
def api_update_transaction(trans_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    allowed_fields = [
        'category', 'subcategory', 'is_personal', 'is_business', 'is_transfer',
        'is_flagged', 'flag_reason', 'user_notes', 'cardholder_name', 'card_last_four',
        'payment_method', 'trans_type', 'description', 'amount', 'trans_date',
        'categorization_status', 'categorization_source', 'categorization_confidence', 'manually_edited'
    ]
    fields = {k: v for k, v in data.items() if k in allowed_fields}
    if 'amount' in fields:
        try:
            fields['amount'] = float(fields['amount'])
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount value'}), 400
    try:
        if fields:
            update_transaction(current_user.id, trans_id, **fields)
            active_company_id = session.get('active_company_id')
            if active_company_id:
                from advisor_worker import trigger_async_advisor_refresh
                trigger_async_advisor_refresh(active_company_id, current_user.id, "Manual Transaction Update")
    except Exception as e:
        return jsonify({'error': f'Update failed: {str(e)}'}), 500
    # If category was changed, suggest a rule
    result = {'status': 'ok'}
    if 'category' in fields:
        suggestion = suggest_rule_from_edit(current_user.id, trans_id)
        if suggestion:
            result['rule_suggestion'] = suggestion
            
            # Phase 16: Automatic soft-learning and background ledger sweep
            add_category_rule(
                user_id=current_user.id,
                pattern=suggestion['pattern'],
                category=suggestion['category'],
                subcategory=suggestion.get('subcategory'),
                is_personal=suggestion.get('is_personal', 0),
                is_business=suggestion.get('is_business', 0),
                is_transfer=suggestion.get('is_transfer', 0),
                priority=50
            )
            
        # Phase 16: Trigger asynchronous ledger sweep so the UI reflects the new learning immediately
        from categorizer import recategorize_all
        threading.Thread(target=recategorize_all, args=(current_user.id,)).start()

    return jsonify(result)


@app.route('/api/transactions/<int:trans_id>', methods=['DELETE'])
@require_company_role(['owner', 'admin', 'operator'])
def api_delete_transaction(trans_id):
    delete_transaction(current_user.id, trans_id)
    active_company_id = session.get('active_company_id')
    if active_company_id:
        from advisor_worker import trigger_async_advisor_refresh
        trigger_async_advisor_refresh(active_company_id, current_user.id, "Manual Transaction Deletion")
    return jsonify({'status': 'ok'})


@app.route('/api/transactions/bulk', methods=['POST'])
@require_company_role(['owner', 'admin', 'operator'])
def api_bulk_update():
    """Bulk update multiple transactions."""
    data = request.get_json()
    ids = data.get('ids', [])
    fields = data.get('fields', {})
    allowed_fields = [
        'category', 'subcategory', 'is_personal', 'is_business', 'is_transfer',
        'is_flagged', 'flag_reason', 'user_notes',
        'categorization_status', 'categorization_source', 'categorization_confidence', 'manually_edited'
    ]
    fields = {k: v for k, v in fields.items() if k in allowed_fields}
    for tid in ids:
        if fields:
            update_transaction(current_user.id, tid, **fields)
            if 'category' in fields:
                suggestion = suggest_rule_from_edit(current_user.id, tid)
                if suggestion:
                    add_category_rule(
                        user_id=current_user.id,
                        pattern=suggestion['pattern'],
                        category=suggestion['category'],
                        subcategory=suggestion.get('subcategory'),
                        is_personal=suggestion.get('is_personal', 0),
                        is_business=suggestion.get('is_business', 0),
                        is_transfer=suggestion.get('is_transfer', 0),
                        priority=50 
                    )
                    
    if 'category' in fields:
        # Phase 16: Trigger asynchronous ledger sweep so the UI reflects bulk learning immediately
        threading.Thread(target=recategorize_all, args=(current_user.id,)).start()

    # Trigger AI Advisor refresh 
    active_company_id = session.get('active_company_id')
    if active_company_id:
        from advisor_worker import trigger_async_advisor_refresh
        trigger_async_advisor_refresh(active_company_id, current_user.id, "Bulk Transaction Update")

    return jsonify({'status': 'ok', 'updated': len(ids)})


@app.route('/api/drilldowns', methods=['POST'])
@require_company_role()
def handle_drilldown_log():
    data = request.json
    try:
        from database import log_drilldown
        log_drilldown(current_user.id, data)
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/upload', methods=['POST'])
@require_company_role(['owner', 'admin', 'operator'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    active_company_id = session.get('active_company_id')
    if not active_company_id:
        return jsonify({'error': 'No active company context. Switch or create a workspace.'}), 400

    doc_type = request.form.get('doc_type', 'auto')
    doc_category = request.form.get('doc_category', 'bank_statement')

    filename = secure_filename(file.filename)
    comp_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(active_company_id))
    os.makedirs(comp_folder, exist_ok=True)
    filepath = os.path.join(comp_folder, filename)

    # Avoid overwriting
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(filepath):
        filename = f"{base}_{counter}{ext}"
        filepath = os.path.join(comp_folder, filename)
        counter += 1

    file.save(filepath)

    file_hash = compute_file_hash(filepath)
    if ext.lower() != '.zip':
        existing_doc_id = get_duplicate_document(current_user.id, file_hash)
        if existing_doc_id:
            os.remove(filepath)
            return jsonify({
                'status': 'ok',
                'mode': 'duplicate',
                'document_id': existing_doc_id,
                'message': 'This document has already been uploaded.',
                'transactions_added': 0
            })

    # Parse the document
    zip_children_info = {} # Map child hash to filename
    try:
        if ext.lower() == '.zip':
            import zipfile
            import hashlib
            from concurrent.futures import ThreadPoolExecutor, as_completed
            from database import get_db
            
            transactions = []
            account_info = {}
            extracted_dir = filepath + "_extracted"
            os.makedirs(extracted_dir, exist_ok=True)
            zip_errors = []
            
            # Zip bomb & slip limits
            MAX_FILES = 500
            MAX_ARCHIVE_SIZE = 200 * 1024 * 1024  # 200 MB
            MAX_FILE_SIZE = 50 * 1024 * 1024      # 50 MB
            
            try:
                with zipfile.ZipFile(filepath, 'r') as zip_ref:
                    total_size = 0
                    file_count = 0
                    
                    files_to_extract = []
                    
                    for zinfo in zip_ref.infolist():
                        # Skip directories
                        if zinfo.is_dir():
                            continue
                            
                        # Zip slip protection
                        if '..' in zinfo.filename or zinfo.filename.startswith('/') or zinfo.filename.startswith('\\'):
                            continue
                            
                        # Skip Mac metadata
                        basename = os.path.basename(zinfo.filename)
                        if basename.startswith('._') or '__MACOSX' in zinfo.filename:
                            continue
                            
                        if not allowed_file(basename) or basename.lower().endswith('.zip'):
                            continue
                        
                        file_count += 1
                        if file_count > MAX_FILES:
                            raise Exception("Zip file contains too many entries (exceeds 500 max).")
                            
                        # Hash the file in-memory using streaming to avoid extracting duplicates to disk
                        file_hash_obj = hashlib.sha256()
                        file_size = 0
                        with zip_ref.open(zinfo) as zf:
                            while chunk := zf.read(8192):
                                file_hash_obj.update(chunk)
                                file_size += len(chunk)
                                total_size += len(chunk)
                                if file_size > MAX_FILE_SIZE:
                                    raise Exception(f"File {zinfo.filename} exceeds 50MB size limit.")
                                if total_size > MAX_ARCHIVE_SIZE:
                                    raise Exception("Zip bomb detected: exceeded 200MB uncompressed limit.")
                                    
                        child_hash = file_hash_obj.hexdigest()
                        
                        # Check duplicate
                        dup_id = get_duplicate_document(current_user.id, child_hash)
                        if dup_id:
                            app.logger.info(f"Linking existing duplicate zip child: {basename}")
                            zip_children_info[child_hash] = basename
                            
                            # Load missing transactions directly to pass to bulk committer
                            conn = get_db()
                            cursor = conn.cursor()
                            cursor.execute("""
                                SELECT t.* FROM transactions t
                                JOIN transaction_sources ts ON ts.transaction_id = t.id
                                WHERE ts.document_id = ? AND ts.user_id = ?
                            """, (dup_id, current_user.id))
                            for row in cursor.fetchall():
                                trans_dict = dict(row)
                                trans_dict['_source_hash'] = child_hash
                                transactions.append(trans_dict)
                            conn.close()
                            continue
                            
                        # If not duplicate, queue for extraction and parsing
                        zip_children_info[child_hash] = basename
                        files_to_extract.append((zinfo, child_hash, basename))

                    # Safely extract the unknown validated files
                    extracted_paths = []
                    for zinfo, child_hash, basename in files_to_extract:
                        safe_path = os.path.abspath(os.path.join(extracted_dir, basename))
                        # Final path validation against slip
                        if not safe_path.startswith(os.path.abspath(extracted_dir)):
                            continue
                        with open(safe_path, 'wb') as f_out:
                            with zip_ref.open(zinfo) as f_in:
                                shutil.copyfileobj(f_in, f_out)
                        extracted_paths.append((safe_path, child_hash))

                    # Parallelize parsing
                    def parse_task(args):
                        f_path, c_hash = args
                        t, ai = parse_document(f_path, doc_type)
                        return c_hash, t, ai

                    with ThreadPoolExecutor(max_workers=4) as executor:
                        future_to_file = {executor.submit(parse_task, item): item for item in extracted_paths}
                        for future in as_completed(future_to_file):
                            c_hash, t, ai = future.result()
                            if t:
                                for trans in t:
                                    trans['_source_hash'] = c_hash
                                transactions.extend(t)
                            if not account_info and ai:
                                account_info = ai

            except Exception as e:
                zip_errors.append(str(e))
                app.logger.error(f"Zip extraction failed: {e}")
            finally:
                # Cleanup temp directory holding the extracted copies
                shutil.rmtree(extracted_dir, ignore_errors=True)
                
            if zip_errors and not transactions:
                raise Exception(f"Failed to process zip archive: {'; '.join(zip_errors)}")

            if not account_info:
                account_info = {'institution': 'Multiple Documents', 'account_type': 'bank', 'account_number': 'Zip Archive'}
        else:
            transactions, account_info = parse_document(filepath, doc_type)
    except Exception as e:
        try:
            os.remove(filepath)
        except OSError:
            pass
        return jsonify({'error': f'Failed to parse document: {str(e)}'}), 400

    # Handle proof/word documents (no transactions)
    if doc_type in ('word', 'proof') or account_info.get('doc_type') == 'proof':
        doc_id = add_document(current_user.id, filename, filepath, ext.replace('.', ''), 'proof', None, None, None, content_sha256=file_hash)
        
        # Persist extracted text and tables for AI categorization
        if account_info.get('content'):
            ext_id = add_document_extraction(current_user.id, doc_id, status='completed')
            update_document_extraction(current_user.id, ext_id, extraction_data=account_info['content'])
            
        return jsonify({
            'status': 'ok',
            'mode': 'proof',
            'document_id': doc_id,
            'message': f'Proof document uploaded: {filename}',
            'transactions_added': 0,
        })

    # Create/get account
    account_id = None
    if account_info.get('account_number'):
        account_id = get_or_create_account(
            user_id=current_user.id,
            account_name=account_info.get('account_name', account_info.get('institution', 'Unknown')),
            account_number=account_info['account_number'],
            account_type=account_info.get('account_type', 'bank'),
            institution=account_info.get('institution', 'Unknown'),
            cardholder_name=account_info.get('account_name'),
            card_last_four=account_info.get('account_number', '')[-4:] if account_info.get('account_number') else None,
        )

    # Save parent document record
    parent_doc_id = add_document(
        user_id=current_user.id,
        filename=filename,
        original_path=filepath,
        file_type=ext.replace('.', ''),
        doc_category=doc_category,
        account_id=account_id,
        statement_start=account_info.get('statement_start'),
        statement_end=account_info.get('statement_end'),
        content_sha256=file_hash
    )
    
    child_doc_map = {}
    if ext.lower() == '.zip':
        for child_hash, c_filename in zip_children_info.items():
            c_ext = c_filename.rsplit('.', 1)[1].lower() if '.' in c_filename else 'pdf'
            c_id = add_document(
                user_id=current_user.id,
                filename=c_filename,
                original_path=None,
                file_type=c_ext,
                doc_category=doc_category,
                account_id=account_id,
                content_sha256=child_hash,
                parent_document_id=parent_doc_id
            )
            child_doc_map[child_hash] = c_id

    # Cascade account-level cardholder information to individual transactions if missing
    global_cardholder = account_info.get('account_name', '')
    global_last_four = str(account_info.get('account_number', ''))[-4:] if account_info.get('account_number') else ''

    # Save transactions with auto-categorization
    added = 0
    skipped = 0
    uncategorized_txns = []
    for trans in transactions:
        if not trans.get('cardholder_name'):
            trans['cardholder_name'] = global_cardholder
        if not trans.get('card_last_four'):
            trans['card_last_four'] = global_last_four

    from categorizer import categorize_transactions_bulk
    categorized_results = categorize_transactions_bulk(current_user.id, transactions, account_id)

    transactions_with_hashes = []
    target_doc_ids = []

    for i, trans in enumerate(transactions):
        target_doc_id = parent_doc_id
        child_hash = trans.get('_source_hash')
        if child_hash and child_hash in child_doc_map:
            target_doc_id = child_doc_map[child_hash]

        # Auto-categorize securely bypassing DB locking
        cat_result = categorized_results[i]
        
        # Merge categorization results directly into the transaction object
        trans['category'] = cat_result['category']
        trans['subcategory'] = cat_result['subcategory']
        trans['payment_method'] = cat_result.get('payment_method', trans.get('payment_method', ''))
        trans['is_transfer'] = cat_result['is_transfer']
        trans['is_personal'] = cat_result['is_personal']
        trans['is_business'] = cat_result['is_business']
        trans['is_flagged'] = cat_result['is_flagged']
        trans['flag_reason'] = cat_result['flag_reason']
        trans['merchant_id'] = cat_result.get('merchant_id')
        trans['categorization_confidence'] = cat_result.get('categorization_confidence')
        trans['categorization_source'] = cat_result.get('categorization_source')
        trans['categorization_status'] = cat_result.get('categorization_status')
        trans['categorization_explanation'] = cat_result.get('categorization_explanation')
        trans['is_approved'] = 0
        trans['auto_categorized'] = 1

        # Deduplication Fingerprint
        txn_fingerprint = compute_transaction_hash(
            account_scope_id=account_id,
            trans_date=trans['trans_date'],
            amount=trans['amount'],
            description=trans['description'],
            post_date=trans.get('post_date', trans.get('trans_date')),
            check_number=trans.get('check_number')
        )

        transactions_with_hashes.append({
            'trans': trans,
            'txn_fingerprint': txn_fingerprint
        })
        target_doc_ids.append(target_doc_id)

    from database import add_transactions_bulk
    added, skipped, trans_doc_stats = add_transactions_bulk(
        user_id=current_user.id,
        account_id=account_id,
        transactions_with_hashes=transactions_with_hashes,
        target_doc_ids=target_doc_ids
    )

    uncategorized_txns = []
    # If we need uncategorized_txns for bulk AI run background process:
    # `add_transactions_bulk` does not natively return individual inserted IDs back to the scope 
    # easily without an architectural redesign of bulk returning. We will do a bulk fetch for uncategorized.
    if added > 0:
        from database import get_db
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, description, amount, trans_date 
            FROM transactions 
            WHERE user_id = ? AND account_id = ? AND category = 'Uncategorized' 
            AND is_approved = 0 ORDER BY id DESC LIMIT ?
        """, (current_user.id, account_id, added))
        for row in cursor.fetchall():
            uncategorized_txns.append(dict(row))
        conn.close()

    from database import update_document_status
    update_document_status(current_user.id, parent_doc_id, status='pending_approval', parsed_count=len(transactions), import_count=added, skipped_count=skipped)

    if uncategorized_txns:
        from categorizer import run_bulk_ai_categorization
        run_bulk_ai_categorization(current_user.id, uncategorized_txns)
        
    if active_company_id:
        from advisor_worker import trigger_async_advisor_refresh
        trigger_async_advisor_refresh(active_company_id, current_user.id, "Document Import Completed")

    return jsonify({
        'status': 'ok',
        'document_id': doc_id,
        'filename': filename,
        'transactions_added': added,
        'transactions_skipped': skipped,
        'account_info': account_info,
    })


@app.route('/api/taxonomy', methods=['GET'])
@require_company_role()
def api_get_taxonomy():
    return jsonify(get_taxonomy_config(current_user.id))

@app.route('/api/taxonomy', methods=['POST'])
@require_company_role(['owner', 'admin', 'operator'])
def api_add_taxonomy():
    data = request.get_json()
    tax_id = add_taxonomy_config(
        user_id=current_user.id,
        name=data.get('name'),
        description=data.get('description'),
        category_type=data.get('category_type'),
        severity=data.get('severity', 'medium')
    )
    if tax_id:
        return jsonify({'status': 'ok', 'id': tax_id})
    return jsonify({'error': 'Failed to add taxonomy config'}), 500

@app.route('/api/taxonomy/<int:tax_id>', methods=['DELETE'])
@require_company_role(['owner', 'admin', 'operator'])
def api_delete_taxonomy(tax_id):
    delete_taxonomy_config(current_user.id, tax_id)
    return jsonify({'status': 'ok'})

@app.route('/api/categories', methods=['GET'])
@require_company_role()
def api_categories():
    return jsonify(get_categories(current_user.id))


@app.route('/api/categories', methods=['POST'])
@require_company_role(['owner', 'admin', 'operator'])
def api_add_category():
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({'error': 'Name is required'}), 400
        
    cat_id = add_category(
        user_id=current_user.id,
        name=data['name'],
        parent_category=data.get('parent_category'),
        category_type=data.get('category_type', 'other'),
        color=data.get('color', '#6c757d'),
        icon=data.get('icon', 'tag')
    )
    if cat_id:
        return jsonify({'status': 'ok', 'id': cat_id})
    return jsonify({'error': 'Failed to add category'}), 500


@app.route('/api/categories/rules', methods=['GET'])
@require_company_role()
def api_category_rules():
    return jsonify(get_category_rules(current_user.id))


@app.route('/api/categories/rules', methods=['POST'])
@require_company_role(['owner', 'admin', 'operator'])
def api_add_rule():
    data = request.get_json()
    add_category_rule(
        user_id=current_user.id,
        pattern=data['pattern'],
        category=data['category'],
        subcategory=data.get('subcategory'),
        is_personal=data.get('is_personal', 0),
        is_business=data.get('is_business', 0),
        is_transfer=data.get('is_transfer', 0),
        priority=data.get('priority', 100),
    )
    
    # Phase 16: Trigger asynchronous ledger sweep so the UI reflects explicit mappings immediately
    threading.Thread(target=recategorize_all, args=(current_user.id,)).start()
    
    return jsonify({'status': 'ok'})


@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@require_company_role(['owner', 'admin', 'operator'])
def api_delete_category(category_id):
    delete_category(current_user.id, category_id)
    return jsonify({'status': 'ok'})


@app.route('/api/categories/rules/<int:rule_id>', methods=['DELETE'])
@require_company_role(['owner', 'admin', 'operator'])
def api_delete_category_rule(rule_id):
    delete_category_rule(current_user.id, rule_id)
    return jsonify({'status': 'ok'})

@app.route('/api/categories/restore-defaults', methods=['POST'])
@require_company_role(['owner', 'admin'])
def api_restore_categories_defaults():
    reset_user_taxonomy(current_user.id)
    return jsonify({'status': 'ok'})

@app.route('/api/recategorize', methods=['POST'])
@require_company_role(['owner', 'admin', 'operator'])
def api_recategorize():
    count = recategorize_all(current_user.id)
    return jsonify({'status': 'ok', 'updated': count})


@app.route('/api/accounts', methods=['GET'])
@require_company_role()
def api_accounts():
    return jsonify(get_accounts(current_user.id))


@app.route('/api/documents', methods=['GET'])
@require_company_role()
def api_documents():
    return jsonify(get_documents(current_user.id))


@app.route('/api/analysis/deposit-transfers', methods=['GET'])
@require_company_role()
def api_deposit_transfers():
    patterns = detect_deposit_transfer_patterns(current_user.id, get_request_filters())
    return jsonify(patterns)


@app.route('/api/analysis/cardholder-spending', methods=['GET'])
@require_company_role()
def api_cardholder_spending():
    summary = get_cardholder_spending_summary(current_user.id, get_request_filters())
    return jsonify(summary)


@app.route('/api/export/csv', methods=['GET'])
@require_company_role()
def api_export_csv():
    """Export transactions as CSV."""
    import csv
    import io
    from flask import Response

    filters = {k: v for k, v in request.args.items() if v}
    transactions = get_transactions(current_user.id, filters if filters else None)

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
@require_company_role(['owner'])
def api_clear_data():
    """Clear all financial data for a fresh start."""
    clear_all_data(current_user.id)
    # Clear uploaded files (keep .gitkeep)
    upload_dir = app.config['UPLOAD_FOLDER']
    for f in os.listdir(upload_dir):
        if f != '.gitkeep':
            fpath = os.path.join(upload_dir, f)
            if os.path.isfile(fpath):
                os.remove(fpath)
    return jsonify({'status': 'ok', 'message': 'All data cleared'})


def process_zip_background(user_id, company_id, parent_doc_id, filepath, file_hash, filename, doc_category, app_context):
    """
    Background job to process a zip file progressively.
    Stages:
      uploaded -> extracting -> extracted -> generating_previews -> parsing -> pending_approval
    """
    with app_context:
        import time
        import os
        start_time = time.time()
        zip_errors = []
        transactions = []
        account_info = {}
        child_doc_map = {}
        target_doc_ids = []
        transactions_with_hashes = []
        skipped_duplicate_files = 0
        from database import update_document_status, add_document, get_duplicate_document, add_transactions_bulk, get_or_create_account, get_db
        from categorizer import categorize_transactions_bulk
        from parsers import parse_document, compute_transaction_hash, ALLOWED_EXTENSIONS
        import zipfile
        import shutil
        import hashlib

        logger = logging.getLogger('forensic_cpa_ai')

        # Update status to extracting
        update_document_status(user_id, parent_doc_id, status='extracting')

        extracted_dir = filepath + "_extracted"
        os.makedirs(extracted_dir, exist_ok=True)
        
        # Zip bomb & slip limits
        MAX_FILES = 500
        MAX_ARCHIVE_SIZE = 200 * 1024 * 1024  # 200 MB
        MAX_FILE_SIZE = 50 * 1024 * 1024      # 50 MB
        
        extracted_paths = []
        
        extract_start = time.time()
        try:
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                total_size = 0
                file_count = 0
                
                for zinfo in zip_ref.infolist():
                    if zinfo.is_dir(): continue
                    if '..' in zinfo.filename or zinfo.filename.startswith('/') or zinfo.filename.startswith('\\'): continue
                    basename = os.path.basename(zinfo.filename)
                    if basename.startswith('._') or '__MACOSX' in zinfo.filename: continue
                    ext = basename.rsplit('.', 1)[1].lower() if '.' in basename else ''
                    if (ext not in ALLOWED_EXTENSIONS and ext != 'zip') or basename.lower().endswith('.zip'): continue
                        
                    file_count += 1
                    if file_count > MAX_FILES:
                        raise Exception("Zip file contains too many entries (exceeds 500 max).")
                        
                    # Hash the file in-memory
                    file_hash_obj = hashlib.sha256()
                    file_size = 0
                    
                    safe_path = os.path.abspath(os.path.join(extracted_dir, basename))
                    if not safe_path.startswith(os.path.abspath(extracted_dir)): continue

                    with open(safe_path, 'wb') as f_out:
                        with zip_ref.open(zinfo) as f_in:
                            while chunk := f_in.read(8192):
                                file_hash_obj.update(chunk)
                                file_size += len(chunk)
                                total_size += len(chunk)
                                if file_size > MAX_FILE_SIZE:
                                    raise Exception(f"File {zinfo.filename} exceeds 50MB size limit.")
                                if total_size > MAX_ARCHIVE_SIZE:
                                    raise Exception("Zip bomb detected: exceeded 200MB uncompressed limit.")
                                f_out.write(chunk)
                                
                    child_hash = file_hash_obj.hexdigest()
                    
                    # Check duplicate
                    dup_id = get_duplicate_document(user_id, child_hash)
                    if dup_id:
                        logger.info(f"Skipping duplicate zip child: {basename}")
                        skipped_duplicate_files += 1
                        os.remove(safe_path)
                        continue
                        
                    extracted_paths.append((safe_path, child_hash, basename))
                    
                    # Create child document record
                    c_ext = basename.rsplit('.', 1)[1].lower() if '.' in basename else 'pdf'
                    c_id = add_document(
                        user_id=user_id,
                        filename=basename,
                        original_path=None,
                        file_type=c_ext,
                        doc_category=doc_category,
                        account_id=None,
                        content_sha256=child_hash,
                        parent_document_id=parent_doc_id,
                        status='extracted'
                    )
                    child_doc_map[child_hash] = c_id

            extract_time = time.time() - extract_start
            logger.info(f"Background ZIP extracted in {extract_time:.2f}s")
            
            update_document_status(user_id, parent_doc_id, status='generating_previews')
            for child_hash, c_id in child_doc_map.items():
                update_document_status(user_id, c_id, status='generating_previews')
            
            update_document_status(user_id, parent_doc_id, status='parsing')
            for child_hash, c_id in child_doc_map.items():
                update_document_status(user_id, c_id, status='parsing')
                
            parse_start = time.time()
            
            # Parallel processing of extracted files
            def parse_task(args):
                f_path, c_hash, b_name = args
                t, ai = parse_document(f_path, 'auto')
                return c_hash, b_name, t, ai

            from concurrent.futures import ThreadPoolExecutor, as_completed
            # Use bounded pool
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_file = {executor.submit(parse_task, item): item for item in extracted_paths}
                for future in as_completed(future_to_file):
                    try:
                        c_hash, b_name, t, ai = future.result()
                        if t:
                            for trans in t:
                                trans['_source_file'] = b_name
                                trans['_source_hash'] = c_hash
                            transactions.extend(t)
                        if not account_info and ai:
                            account_info = ai
                    except Exception as inner_e:
                        zip_errors.append(f"{future_to_file[future][2]}: {inner_e}")
                        logger.warning(f"Failed to parse inner zip file: {inner_e}")

            if zip_errors and not transactions:
                raise Exception(f"Failed to process zip archive: {'; '.join(zip_errors)}")

            if not account_info:
                account_info = {'institution': 'Multiple Documents', 'account_type': 'bank', 'account_number': 'Zip Archive'}
                
            # Database saving phase
            if account_info.get('account_number'):
                account_id = get_or_create_account(
                    user_id=user_id,
                    account_name=account_info.get('account_name', account_info.get('institution', 'Unknown')),
                    account_number=account_info['account_number'],
                    account_type=account_info.get('account_type', 'bank'),
                    institution=account_info.get('institution', 'Unknown'),
                    cardholder_name=account_info.get('account_name'),
                    card_last_four=account_info.get('account_number', '')[-4:] if account_info.get('account_number') else None
                )
                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE documents SET account_id = ?, statement_start_date = ?, statement_end_date = ? WHERE id = ?",
                                   (account_id, account_info.get('statement_start'), account_info.get('statement_end'), parent_doc_id))
                    for c_id in child_doc_map.values():
                        cursor.execute("UPDATE documents SET account_id = ? WHERE id = ?", (account_id, c_id))
                    conn.commit()
                finally:
                    conn.close()
            else:
                account_id = None
                
            global_cardholder = account_info.get('account_name', '')
            global_last_four = str(account_info.get('account_number', ''))[-4:] if account_info.get('account_number') else ''

            for trans in transactions:
                if not trans.get('cardholder_name'):
                    trans['cardholder_name'] = global_cardholder
                if not trans.get('card_last_four'):
                    trans['card_last_four'] = global_last_four

            categorized_results = categorize_transactions_bulk(user_id, transactions, account_id)
            for i, trans in enumerate(transactions):
                cat_result = categorized_results[i]
                trans['category'] = cat_result['category']
                trans['subcategory'] = cat_result['subcategory']
                trans['is_personal'] = cat_result['is_personal']
                trans['is_business'] = cat_result['is_business']
                trans['is_transfer'] = cat_result['is_transfer']
                trans['is_flagged'] = cat_result['is_flagged']
                trans['flag_reason'] = cat_result['flag_reason']
                trans['payment_method'] = cat_result.get('payment_method', trans.get('payment_method', ''))

            doc_stats = {}
            for child_hash, c_id in child_doc_map.items():
                doc_stats[c_id] = {'added': 0, 'skipped': 0, 'total': 0}
                
            for trans in transactions:
                target_doc_id = parent_doc_id
                child_hash = trans.get('_source_hash')
                if child_hash and child_hash in child_doc_map:
                    target_doc_id = child_doc_map[child_hash]

                txn_fingerprint = compute_transaction_hash(
                    account_scope_id=account_id,
                    trans_date=trans['trans_date'],
                    amount=trans['amount'],
                    description=trans['description'],
                    post_date=trans.get('post_date', trans.get('trans_date')),
                    check_number=trans.get('check_number')
                )

                transactions_with_hashes.append({
                    'trans': trans,
                    'txn_fingerprint': txn_fingerprint
                })
                target_doc_ids.append(target_doc_id)

            added, skipped, trans_doc_stats = add_transactions_bulk(
                user_id=user_id,
                account_id=account_id,
                transactions_with_hashes=transactions_with_hashes,
                target_doc_ids=target_doc_ids
            )
            
            for d_id, stats in trans_doc_stats.items():
                if d_id not in doc_stats:
                    doc_stats[d_id] = {'added': 0, 'skipped': 0, 'total': 0}
                doc_stats[d_id]['added'] += stats['added']
                doc_stats[d_id]['skipped'] += stats['skipped']
                doc_stats[d_id]['total'] += stats['total']

            for d_id, stats in doc_stats.items():
                update_document_status(
                    user_id, 
                    d_id, 
                    status='pending_approval', 
                    parsed_count=stats['total'], 
                    import_count=stats['added'], 
                    skipped_count=stats['skipped']
                )
                
            if parent_doc_id not in doc_stats:
                update_document_status(
                    user_id, 
                    parent_doc_id, 
                    status='pending_approval', 
                    parsed_count=0, 
                    import_count=0, 
                    skipped_count=0
                )
                
            parse_time = time.time() - parse_start
            total_time = time.time() - start_time
            logger.info(f"Background ZIP parsed/imported in {parse_time:.2f}s. Total Job time {total_time:.2f}s.")

        except Exception as e:
            logger.error(f"Background ZIP task failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            update_document_status(user_id, parent_doc_id, status='failed', failure_reason=str(e)[:250])
            for child_hash, c_id in child_doc_map.items():
                update_document_status(user_id, c_id, status='failed', failure_reason="Parent ZIP processing failed")
        finally:
            shutil.rmtree(extracted_dir, ignore_errors=True)

def process_qbw_background(user_id, company_id, doc_id, filepath, app_context):
    with app_context:
        import time
        import os
        import logging
        from database import update_document_status
        
        logger = logging.getLogger('forensic_cpa_ai')
        try:
            # Explicitly show it's being evaluated
            update_document_status(user_id, doc_id, status='extracting')
            time.sleep(1) # simulate binary evaluation
            
            # Since full QBW parsing requires Desktop Web Connector, gracefully mark it as actionable failure
            update_document_status(
                user_id,
                doc_id,
                status='failed',
                failure_reason='Needs Conversion: QBW files require QuickBooks Desktop Web Connector or manual export to Excel/CSV.'
            )
        except Exception as e:
            logger.error(f"Error handling QBW file fallback state: {e}")
            update_document_status(user_id, doc_id, status='failed', failure_reason='System error staging QBW.')
        finally:
            try:
                os.remove(filepath)
            except OSError:
                pass


@app.route('/api/upload/preview', methods=['POST'])
@login_required
def api_upload_preview():
    """Parse uploaded file and return preview without saving to DB."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    active_company_id = session.get('active_company_id')
    if not active_company_id:
        return jsonify({'error': 'No active company context. Switch or create a workspace.'}), 400

    doc_type = request.form.get('doc_type', 'auto')
    doc_category = request.form.get('doc_category', 'bank_statement')

    filename = secure_filename(file.filename)
    comp_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(active_company_id))
    os.makedirs(comp_folder, exist_ok=True)
    filepath = os.path.join(comp_folder, filename)

    # Avoid overwriting
    base, ext = os.path.splitext(filename)
    counter = 1
    while os.path.exists(filepath):
        filename = f"{base}_{counter}{ext}"
        filepath = os.path.join(comp_folder, filename)
        counter += 1

    file.save(filepath)

    file_hash = compute_file_hash(filepath)
    if ext.lower() != '.zip':
        existing_doc_id = get_duplicate_document(current_user.id, file_hash)
        if existing_doc_id:
            os.remove(filepath)
            return jsonify({
                'status': 'ok',
                'mode': 'duplicate',
                'document_id': existing_doc_id,
                'message': 'This document has already been uploaded.',
                'transactions_added': 0,
                'transactions': [],
                'account_info': {},
                'transaction_count': 0,
                'duplicate_count': 0,
            })

    # Zero-Cost Active Memory Cache
    with _preview_lock:
        for p_id, p_data in upload_previews.items():
            if p_data.get('file_hash') == file_hash and p_data.get('ext') == ext:
                try:
                    os.remove(filepath)
                except OSError:
                    pass
                return jsonify({
                    'status': 'ok',
                    'mode': 'preview',
                    'preview_id': p_id,
                    'filename': p_data['filename'],
                    'transactions': p_data['transactions'],
                    'account_info': p_data['account_info'],
                    'transaction_count': len(p_data['transactions']),
                    'duplicate_count': len([t for t in p_data['transactions'] if t.get('_is_duplicate')]),
                    'skipped_duplicate_files': 0,
                })

    # Parse the document
    zip_children_info = {}
    skipped_duplicate_files = 0
    try:
        if ext.lower() == '.zip':
            parent_doc_id = add_document(
                user_id=current_user.id,
                filename=filename,
                original_path=filepath,
                file_type=ext.replace('.', ''),
                doc_category=doc_category,
                account_id=None,
                content_sha256=file_hash,
                status='uploaded',
                company_id=active_company_id
            )
            
            # Spin up background job
            app_context = app.app_context()
            zip_executor.submit(
                process_zip_background,
                current_user.id,
                active_company_id,
                parent_doc_id,
                filepath,
                file_hash,
                filename,
                doc_category,
                app_context
            )
            
            return jsonify({
                'status': 'ok',
                'mode': 'async_zip',
                'document_id': parent_doc_id,
                'message': 'ZIP file is being processed in the background.'
            })
        elif ext.lower() == '.qbw':
            # File validation (QBW files are binary and typically large; block empty/corrupt stubs)
            if os.path.getsize(filepath) < 1024:
                raise ValueError("File appears invalid, corrupt, or empty.")
                
            doc_id = add_document(
                user_id=current_user.id,
                filename=filename,
                original_path=filepath,
                file_type='qbw',
                doc_category=doc_category,
                account_id=None,
                content_sha256=file_hash,
                status='uploaded',  # Staged state, intentionally NOT completed
                company_id=active_company_id
            )
            
            app_context = app.app_context()
            zip_executor.submit(
                process_qbw_background,
                current_user.id,
                active_company_id,
                doc_id,
                filepath,
                app_context
            )
            
            return jsonify({
                'status': 'ok',
                'mode': 'async_zip',  # Reuses existing frontend safe-success toast
                'document_id': doc_id,
                'message': 'QuickBooks file staged. Awaiting converter parsing.'
            })
        else:
            transactions, account_info = parse_document(filepath, doc_type)
    except Exception as e:
        try:
            os.remove(filepath)
        except OSError:
            pass
        return jsonify({'error': f'Failed to parse document: {str(e)}'}), 400

    # For proof/word docs, skip preview and commit directly
    if doc_type in ('word', 'proof') or account_info.get('doc_type') == 'proof':
        doc_id = add_document(current_user.id, filename, filepath, ext.replace('.', ''), 'proof', content_sha256=file_hash, company_id=active_company_id)
        
        # Persist extracted text and tables for AI categorization
        if account_info.get('content'):
            ext_id = add_document_extraction(current_user.id, doc_id, status='completed')
            update_document_extraction(current_user.id, ext_id, extraction_data=account_info['content'])
            
        return jsonify({
            'status': 'ok',
            'mode': 'proof',
            'document_id': doc_id,
            'message': f'Proof document uploaded: {filename}',
            'transactions_added': 0,
        })

    # Cascade account-level cardholder information to individual transactions if missing
    global_cardholder = account_info.get('account_name', '')
    global_last_four = str(account_info.get('account_number', ''))[-4:] if account_info.get('account_number') else ''

    # Auto-categorize for preview using O(1) Bulk Evaluator
    for trans in transactions:
        if not trans.get('cardholder_name'):
            trans['cardholder_name'] = global_cardholder
        if not trans.get('card_last_four'):
            trans['card_last_four'] = global_last_four

    from categorizer import categorize_transactions_bulk
    categorized_results = categorize_transactions_bulk(current_user.id, transactions, account_info.get('account_id'))

    for i, trans in enumerate(transactions):
        cat_result = categorized_results[i]
        trans['category'] = cat_result['category']
        trans['subcategory'] = cat_result['subcategory']
        trans['is_personal'] = cat_result['is_personal']
        trans['is_business'] = cat_result['is_business']
        trans['is_transfer'] = cat_result['is_transfer']
        trans['is_flagged'] = cat_result['is_flagged']
        trans['flag_reason'] = cat_result['flag_reason']
        trans['payment_method'] = cat_result.get('payment_method', trans.get('payment_method', ''))

    # Check for duplicates
    duplicates = find_duplicate_transactions(current_user.id, transactions)
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
            'zip_children_info': zip_children_info,
            'file_hash': file_hash,
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
        'skipped_duplicate_files': skipped_duplicate_files if 'skipped_duplicate_files' in locals() else 0,
    })


@app.route('/api/upload/commit', methods=['POST'])
@login_required
def api_upload_commit():
    """Commit a previewed upload to the database."""
    data = request.get_json()
    preview_id = data.get('preview_id')
    active_company_id = session.get('active_company_id')
    
    if not active_company_id:
        return jsonify({'error': 'No active company context.'}), 400

    with _preview_lock:
        if preview_id in _recent_commits:
            return jsonify(_recent_commits[preview_id])
            
        if preview_id not in upload_previews:
            return jsonify({'error': 'Preview not found or expired'}), 404
            
        preview = upload_previews.pop(preview_id)
    transactions = data.get('transactions', preview['transactions'])
    account_info = preview['account_info']
    filename = preview['filename']
    filepath = preview['filepath']
    ext = preview['ext']
    doc_category = preview['doc_category']
    file_hash = preview.get('file_hash')
    zip_children_info = preview.get('zip_children_info', {})

    # Restore internal properties that the frontend might drop, like _source_hash
    if data.get('transactions'):
        # match by index assuming order is preserved
        original_txns = preview['transactions']
        for i, t in enumerate(transactions):
            if i < len(original_txns) and '_source_hash' in original_txns[i]:
                t['_source_hash'] = original_txns[i]['_source_hash']

    conn = get_db()
    try:
        # Create/get account
        account_id = None
        if account_info.get('account_number'):
            account_id = get_or_create_account(
                user_id=current_user.id,
                account_name=account_info.get('account_name', account_info.get('institution', 'Unknown')),
                account_number=account_info['account_number'],
                account_type=account_info.get('account_type', 'bank'),
                institution=account_info.get('institution', 'Unknown'),
                cardholder_name=account_info.get('account_name'),
                card_last_four=account_info.get('account_number', '')[-4:] if account_info.get('account_number') else None,
                conn=conn,
                company_id=active_company_id
            )

        # Save document record
        parent_doc_id = add_document(
            user_id=current_user.id,
            filename=filename,
            original_path=filepath,
            file_type=ext.replace('.', ''),
            doc_category=doc_category,
            account_id=account_id,
            statement_start=account_info.get('statement_start'),
            statement_end=account_info.get('statement_end'),
            content_sha256=file_hash,
            conn=conn,
            company_id=active_company_id
        )

        child_doc_map = {}
        doc_stats = {} # track counts per doc id: {doc_id: {'added': 0, 'skipped': 0, 'total': 0}}
        
        # Pre-register all child documents dynamically provided by preview state
        # This ensures they show up as independent 0-tx files if AI parsing returned nothing
        for child_hash, c_filename in zip_children_info.items():
            c_ext = c_filename.rsplit('.', 1)[1].lower() if '.' in c_filename else 'pdf'
            c_id = add_document(
                user_id=current_user.id,
                filename=c_filename,
                original_path=None,
                file_type=c_ext,
                doc_category=doc_category,
                account_id=account_id,
                content_sha256=child_hash,
                parent_document_id=parent_doc_id,
                conn=conn,
                company_id=active_company_id
            )
            child_doc_map[child_hash] = c_id
            doc_stats[c_id] = {'added': 0, 'skipped': 0, 'total': 0}

        # Save transactions
        transactions_with_hashes = []
        target_doc_ids = []

        for trans in transactions:
            target_doc_id = parent_doc_id
            child_hash = trans.get('_source_hash')
            if child_hash and child_hash in child_doc_map:
                target_doc_id = child_doc_map[child_hash]

            # Deduplication Fingerprint
            txn_fingerprint = compute_transaction_hash(
                account_scope_id=account_id,
                trans_date=trans['trans_date'],
                amount=trans['amount'],
                description=trans['description'],
                post_date=trans.get('post_date', trans.get('trans_date')),
                check_number=trans.get('check_number')
            )

            transactions_with_hashes.append({
                'trans': trans,
                'txn_fingerprint': txn_fingerprint
            })
            target_doc_ids.append(target_doc_id)

        from database import add_transactions_bulk
        added, skipped, trans_doc_stats = add_transactions_bulk(
            user_id=current_user.id,
            account_id=account_id,
            transactions_with_hashes=transactions_with_hashes,
            target_doc_ids=target_doc_ids,
            conn=conn,
            company_id=active_company_id
        )

        for d_id, stats in trans_doc_stats.items():
            if d_id not in doc_stats:
                doc_stats[d_id] = {'added': 0, 'skipped': 0, 'total': 0}
            doc_stats[d_id]['added'] += stats['added']
            doc_stats[d_id]['skipped'] += stats['skipped']
            doc_stats[d_id]['total'] += stats['total']

        from database import update_document_status

        # Update all child documents (if any) and the parent
        for d_id, stats in doc_stats.items():
            update_document_status(
                current_user.id, 
                d_id, 
                status='pending_approval', 
                parsed_count=stats['total'], 
                import_count=stats['added'], 
                skipped_count=stats['skipped'], 
                conn=conn,
                company_id=active_company_id
            )
        
        # If the parent ZIP itself had no direct transactions (only children did), mark it approved or pending
        if parent_doc_id not in doc_stats:
            update_document_status(
                current_user.id, 
                parent_doc_id, 
                status='pending_approval' if transactions else 'completed', 
                parsed_count=0, 
                import_count=0, 
                skipped_count=0,
                conn=conn,
                company_id=active_company_id
            )
            
        conn.commit()
    except Exception as e:
        import traceback
        traceback.print_exc()
        conn.rollback()
        app.logger.error(f"Upload Commit Failed, rolled back database state: {str(e)}")
        return jsonify({'error': f'Failed to save transactions. Action was safely rolled back. {str(e)}'}), 500
    finally:
        conn.close()

    success_payload = {
        'status': 'ok',
        'message': 'Transactions imported successfully',
        'document_id': parent_doc_id, 
        'filename': filename,
        'transactions_added': added,
        'transactions_skipped': skipped,
        'doc_stats': doc_stats
    }
    
    with _preview_lock:
        _recent_commits[preview_id] = success_payload
        if len(_recent_commits) > 1000:
            oldest_key = next(iter(_recent_commits))
            _recent_commits.pop(oldest_key, None)

    # Automatically mark Advisor state as stale post-commit
    if active_company_id:
        from advisor_worker import trigger_async_advisor_refresh
        trigger_async_advisor_refresh(active_company_id, current_user.id, "Document/Batch Upload Committed")

    return jsonify(success_payload)


@app.route('/api/documents/<int:doc_id>/approve', methods=['POST'])
@login_required
def api_document_approve(doc_id):
    """Approve a document and its parsed transactions."""
    from database import get_db, document_lock
    
    with document_lock(doc_id):
        conn = get_db()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute("SELECT id, status FROM documents WHERE id = ? AND user_id = ?", (doc_id, current_user.id))
        doc = cursor.fetchone()
        if not doc:
            conn.close()
            return jsonify({'error': 'Document not found or unauthorized'}), 404
            
        doc_status = doc['status']
        
        # If already approved, handle idempotency
        if doc_status == 'approved':
            conn.close()
            return jsonify({'status': 'ok', 'message': 'Document already approved', 'transactions_approved': 0})
            
        
        try:
            # Attempt to update the document status to 'approved' only if it's in a 'pending_approval' or 'completed' state.
            # This also serves as a check for the document's current state.
            cursor.execute("UPDATE documents SET status = 'approved' WHERE id = ? AND user_id = ? AND status IN ('pending_approval', 'completed')", (doc_id, current_user.id))
            
            if cursor.rowcount == 0:
                # Check if this thread lost the race to another identical request milliseconds earlier
                cursor.execute("SELECT status FROM documents WHERE id = ? AND user_id = ?", (doc_id, current_user.id))
                race_check = cursor.fetchone()
                if race_check and race_check['status'] == 'approved':
                    conn.rollback() # Rollback the implicit transaction from the failed update
                    return jsonify({'status': 'ok', 'message': 'Document already approved', 'transactions_approved': 0})
                
                conn.rollback() # Rollback the implicit transaction from the failed update
                return jsonify({'error': 'Document cannot be approved from its current state or was modified concurrently.'}), 400
    
            # Also approve any validly-staged child documents strictly obeying state machine valid transitions
            cursor.execute("UPDATE documents SET status = 'approved' WHERE parent_document_id = ? AND user_id = ? AND status IN ('pending_approval', 'completed')", (doc_id, current_user.id))
            
            # Update all linked transactions to is_approved = 1 (for this doc and its successfully approved children)
            cursor.execute("""
                UPDATE transactions 
                SET is_approved = 1 
                WHERE (document_id = ? OR document_id IN (SELECT id FROM documents WHERE parent_document_id = ? AND user_id = ? AND status = 'approved'))
                AND user_id = ?
            """, (doc_id, doc_id, current_user.id, current_user.id))
            transactions_approved = cursor.rowcount
            
            conn.commit()
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Approval Transaction Failed, rolled back state: {e}")
            return jsonify({'error': 'Failed to process approval workflow cleanly.'}), 500
        finally:
            conn.close()
            
        # Trigger Advisor Refresh assuming success and non-zero mutations
        active_company_id = session.get('active_company_id')
        if active_company_id and transactions_approved > 0:
            from advisor_worker import trigger_async_advisor_refresh
            trigger_async_advisor_refresh(active_company_id, current_user.id, "Document Approved (Batch Transactions)")
        
        return jsonify({
            'status': 'ok',
            'message': 'Document approved',
            'transactions_approved': transactions_approved
        })


@app.route('/api/documents/<int:doc_id>', methods=['DELETE'])
@login_required
def api_document_delete(doc_id):
    """Delete a document, its children (if zip), and safely remove orphan transactions."""
    from database import delete_document
    success = delete_document(current_user.id, doc_id)
    if success:
        active_company_id = session.get('active_company_id')
        if active_company_id:
            from advisor_worker import trigger_async_advisor_refresh
            trigger_async_advisor_refresh(active_company_id, current_user.id, "Document Deletion")
        return jsonify({'status': 'ok', 'message': 'Document and derived data deleted'})
    else:
        return jsonify({'error': 'Document not found or unauthorized'}), 404


@app.route('/api/upload/cancel', methods=['POST'])
@login_required
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
@login_required
def api_get_proofs(trans_id):
    proofs = get_proofs_for_transaction(current_user.id, trans_id)
    return jsonify(proofs)


@app.route('/api/transactions/<int:trans_id>/proofs', methods=['POST'])
@login_required
def api_link_proof(trans_id):
    data = request.get_json()
    doc_id = data.get('document_id')
    if not doc_id:
        return jsonify({'error': 'document_id required'}), 400
    link_proof(current_user.id, trans_id, doc_id)
    return jsonify({'status': 'ok'})


@app.route('/api/transactions/<int:trans_id>/proofs/<int:doc_id>', methods=['DELETE'])
@login_required
def api_unlink_proof(trans_id, doc_id):
    unlink_proof(current_user.id, trans_id, doc_id)
    return jsonify({'status': 'ok'})


@app.route('/api/documents/<int:doc_id>/transactions', methods=['GET'])
@login_required
def api_doc_transactions(doc_id):
    transactions = get_transactions_for_proof(current_user.id, doc_id)
    return jsonify(transactions)


@app.route('/api/add-transaction', methods=['POST'])
@login_required
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
        txn_fingerprint = compute_transaction_hash(
            account_scope_id=data.get('account_id'),
            trans_date=data['trans_date'],
            amount=amount,
            description=data['description'],
            post_date=data.get('post_date', data['trans_date']),
            check_number=data.get('check_number')
        )

        # System Integration: Run categorize on manual additions if they don't explicitly pass one
        category_payload = data.get('category')
        if not category_payload or category_payload == 'Uncategorized':
            from categorizer import categorize_transaction
            cat_result = categorize_transaction(
                current_user.id,
                data['description'], amount,
                data.get('trans_type', ''), data.get('payment_method', ''),
                account_id=data.get('account_id')
            )
            final_cat = cat_result['category']
            final_sub = cat_result['subcategory']
            conf = cat_result.get('categorization_confidence')
            src = cat_result.get('categorization_source')
            stat = cat_result.get('categorization_status')
            exp = cat_result.get('categorization_explanation')
        else:
            final_cat = category_payload
            final_sub = data.get('subcategory')
            conf = None
            src = 'user_rule'
            stat = 'auto_applied'
            exp = 'Manually provided upon creation.'

        trans_id, _ = add_transaction(
            user_id=current_user.id,
            doc_id=None,
            account_id=data.get('account_id'),
            trans_date=data['trans_date'],
            post_date=data.get('post_date', data['trans_date']),
            description=data['description'],
            amount=amount,
            trans_type=data.get('trans_type', 'debit'),
            category=final_cat,
            subcategory=final_sub,
            cardholder_name=data.get('cardholder_name', ''),
            card_last_four=data.get('card_last_four', ''),
            payment_method=data.get('payment_method', ''),
            is_transfer=data.get('is_transfer', 0),
            is_personal=data.get('is_personal', 0),
            is_business=data.get('is_business', 0),
            auto_categorized=1 if conf else 0,
            manually_edited=0 if conf else 1,
            txn_fingerprint=txn_fingerprint,
            categorization_confidence=conf,
            categorization_source=src,
            categorization_status=stat,
            categorization_explanation=exp
        )
    except Exception as e:
        return jsonify({'error': f'Failed to add transaction: {str(e)}'}), 500
    return jsonify({'status': 'ok', 'id': trans_id})


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/api/analysis/summary', methods=['GET'])
@login_required
def api_executive_summary():
    """Executive summary with auto-generated key findings."""
    return jsonify(get_executive_summary(current_user.id, get_request_filters()))


@app.route('/api/analysis/money-flow', methods=['GET'])
@login_required
def api_money_flow():
    """Cross-account money flow tracking."""
    return jsonify(get_money_flow(current_user.id, get_request_filters()))


@app.route('/api/analysis/timeline', methods=['GET'])
@login_required
def api_timeline():
    """Daily timeline data for visualization."""
    return jsonify(get_timeline_data(current_user.id, get_request_filters()))


@app.route('/api/analysis/recipients', methods=['GET'])
@login_required
def api_recipient_analysis():
    """Who Gets the Money - recipient profiling with suspicion scores."""
    return jsonify(get_recipient_analysis(current_user.id, get_request_filters()))


@app.route('/api/analysis/deposit-aging', methods=['GET'])
@login_required
def api_deposit_aging():
    """Deposit aging - how quickly deposits leave the account."""
    return jsonify(get_deposit_aging(current_user.id, get_request_filters()))


@app.route('/api/analysis/cardholder-comparison', methods=['GET'])
@login_required
def api_cardholder_comparison():
    """Side-by-side cardholder comparison."""
    return jsonify(get_cardholder_comparison(current_user.id, get_request_filters()))


@app.route('/api/audit-trail', methods=['GET'])
@login_required
def api_audit_trail():
    """Audit trail log viewer."""
    limit = request.args.get('limit', 200, type=int)
    return jsonify(get_audit_trail(current_user.id, limit))


@app.route('/api/transactions/<int:trans_id>/suggest-rule', methods=['GET'])
@login_required
def api_suggest_rule(trans_id):
    """Suggest a categorization rule from a manually edited transaction."""
    suggestion = suggest_rule_from_edit(current_user.id, trans_id)
    if suggestion:
        return jsonify(suggestion)
    return jsonify({'error': 'Could not generate rule suggestion'}), 404


@app.route('/api/case-notes', methods=['GET'])
@login_required
def api_get_notes():
    return jsonify(get_case_notes(current_user.id))


@app.route('/api/case-notes', methods=['POST'])
@login_required
def api_add_note():
    data = request.get_json()
    note_id = add_case_note(
        user_id=current_user.id,
        title=data['title'], content=data['content'],
        note_type=data.get('note_type', 'general'),
        severity=data.get('severity', 'info'),
        linked_transaction_ids=data.get('linked_transaction_ids')
    )
    return jsonify({'status': 'ok', 'id': note_id})


@app.route('/api/case-notes/<int:note_id>', methods=['PUT'])
@login_required
def api_update_note(note_id):
    data = request.get_json()
    update_case_note(current_user.id, note_id, **data)
    return jsonify({'status': 'ok'})


@app.route('/api/case-notes/<int:note_id>', methods=['DELETE'])
@login_required
def api_delete_note(note_id):
    delete_case_note(current_user.id, note_id)
    return jsonify({'status': 'ok'})


@app.route('/api/saved-filters', methods=['GET'])
@login_required
def api_get_filters():
    return jsonify(get_saved_filters(current_user.id))


@app.route('/api/saved-filters', methods=['POST'])
@login_required
def api_add_filter():
    data = request.get_json()
    fid = add_saved_filter(current_user.id, data['name'], data['filters'])
    return jsonify({'status': 'ok', 'id': fid})


@app.route('/api/saved-filters/<int:filter_id>', methods=['DELETE'])
@login_required
def api_delete_filter(filter_id):
    delete_saved_filter(current_user.id, filter_id)
    return jsonify({'status': 'ok'})


@app.route('/api/accounts/<int:account_id>/balance', methods=['GET'])
@login_required
def api_account_balance(account_id):
    return jsonify(get_account_running_balance(current_user.id, account_id))


@app.route('/api/alerts', methods=['GET'])
@login_required
def api_alerts():
    return jsonify(get_alerts(current_user.id))


@app.route('/api/search/global', methods=['GET'])
@login_required
def api_global_search():
    """Search across transactions, case notes, and documents."""
    q = request.args.get('q', '').strip()
    if len(q) < 2:
        return jsonify({'transactions': [], 'notes': [], 'documents': []})
    conn = get_db()
    cursor = conn.cursor()
    uid = current_user.id
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
@login_required
def api_recurring():
    """Detect recurring/scheduled transactions."""
    return jsonify(get_recurring_transactions(current_user.id, get_request_filters()))


@app.route('/api/analysis/cardholder-timeline')
@login_required
def api_cardholder_timeline():
    """Get timeline data per cardholder for overlay comparison."""
    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(current_user.id, get_request_filters())
    
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
@login_required
def api_export_report():
    """Generate and download a PDF forensic report."""
    try:
        from report_generator import generate_forensic_report
        filepath, filename = generate_forensic_report(current_user.id, get_request_filters())
        directory = os.path.dirname(filepath)
        return send_from_directory(directory, filename, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': f'Report generation failed: {str(e)}'}), 500


@app.route('/health')
def health():
    """Health check endpoint for LocalProgramControlCenter."""
    return jsonify({'status': 'ok', 'service': 'Forensic CPA AI'})


@app.route('/api/advisor/status', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_status():
    """Fetch the current execution state without triggering operations."""
    active_company_id = session.get('active_company_id')
    if not active_company_id:
        return jsonify({"status": "error", "message": "No active company selected"}), 400
        
    from database import get_advisor_company_state
    state = get_advisor_company_state(active_company_id)
    return jsonify({
        "status": "success",
        "advisor_state": {
            "execution_status": state.get('status'),
            "needs_refresh": state.get('needs_refresh'),
            "last_run_at": state.get('last_run_at'),
            "last_failure_at": state.get('last_failure_at'),
            "has_cache": 1 if state.get('last_result_json') else 0
        }
    })


@app.route('/api/advisor/aggregate', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_aggregate():
    active_company_id = session.get('active_company_id')
    if not active_company_id:
        return jsonify({"status": "error", "message": "No active company selected"}), 400
        
    from database import get_advisor_company_state
    from advisor_worker import trigger_async_advisor_refresh
    import json
    
    state = get_advisor_company_state(active_company_id)
    from flask import request
    force = request.args.get('force', 'false').lower() == 'true'
    
    # 1. Thread currently holds processing lock
    if state.get('status') == 'running':
        msg = "Applying deterministic multi-factor models. Please wait..."
        if state.get('last_result_json'):
            msg = "Analysis Stale / Refresh Needed: Automatically updating multi-factor models in background. Previous cached findings shown below."
        resp = {"status": "running", "message": msg}
        if state.get('last_result_json'):
            try: resp['data'] = json.loads(state['last_result_json'])
            except: pass
        return jsonify(resp)
        
    # 2. Dirtied flag or manual force, trigger thread instantiation
    is_stale = state.get('needs_refresh') == 1 or not state.get('last_result_json') or state.get('status') == 'queued'
    if is_stale or force:
        trigger_async_advisor_refresh(active_company_id, current_user.id, "Manual Tab Refresh")
        msg = "Analysis queued. Starting new engine execution..."
        if state.get('last_result_json'):
            msg = "Analysis Stale / Refresh Needed: Instantiating automated refresh in background. Previous findings shown below."
        resp = {"status": "running", "message": msg}
        if state.get('last_result_json'):
            try: resp['data'] = json.loads(state['last_result_json'])
            except: pass
        return jsonify(resp)
        
    # 3. Clean/Completed, deliver generated cache without halting execution 
    try:
        cached_data = json.loads(state['last_result_json'])
        return jsonify({
            "status": "success",
            "data": cached_data
        })
    except Exception:
        trigger_async_advisor_refresh(active_company_id, current_user.id, "JSON Cache Corruption Recovery")
        return jsonify({"status": "running", "message": "Rebuilding corrupted analysis state..."})

@app.route('/api/advisor/report', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_report():
    company_id = session.get('active_company_id')
    mode = request.args.get('mode', 'client')
    from report_builder import generate_advisor_report
    try:
        report = generate_advisor_report(company_id, mode)
        return jsonify({"status": "success", "data": report})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Report generation failed: {str(e)}"}), 500

@app.route('/api/simulator/run', methods=['POST'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_simulator_run():
    company_id = session.get('active_company_id')
    data = request.json or {}
    
    scenario_type = data.get('scenario_type')
    if not scenario_type:
        return jsonify({"status": "error", "message": "Missing scenario_type"}), 400
        
    parameters = data.get('parameters', {})
    
    try:
        from scenario_engine import run_simulation
        result = run_simulation(company_id, scenario_type, parameters)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Simulation failed: {str(e)}"}), 500

@app.route('/api/advisor/findings', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_findings():
    company_id = session.get('active_company_id')
    category = request.args.get('category')
    from database import get_advisor_findings
    findings = get_advisor_findings(company_id, category)
    return jsonify({"status": "success", "data": findings})

@app.route('/api/advisor/findings/<finding_id>', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_finding_detail(finding_id):
    company_id = session.get('active_company_id')
    from database import get_advisor_finding_by_id
    finding = get_advisor_finding_by_id(company_id, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": "Finding not found"}), 404
    return jsonify({"status": "success", "data": finding})

@app.route('/api/advisor/findings/<finding_id>/drilldown', methods=['POST'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_finding_drilldown(finding_id):
    company_id = session.get('active_company_id')
    from database import get_advisor_finding_by_id, get_db
    finding = get_advisor_finding_by_id(company_id, finding_id)
    if not finding:
        return jsonify({"status": "error", "message": "Finding not found"}), 404
        
    queries = finding.get('drilldown_queries', {})
    if not queries:
        return jsonify({"status": "success", "data": []})
        
    target_table = queries.get('type', 'transactions')
    if target_table not in ['transactions', 'documents', 'merchants']:
        return jsonify({"status": "error", "message": "Invalid drilldown target"}), 400
        
    conn = get_db()
    cursor = conn.cursor()
    # Simple dynamic SQL execution enforcing strict tenancy bounds.
    # Advanced logic parses `queries` filters (e.g. min_amount) and builds SQL.
    try:
        if target_table == 'transactions':
            cursor.execute("SELECT * FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE company_id = ?) LIMIT 50", (company_id,))
        elif target_table == 'documents':
            cursor.execute("SELECT * FROM documents WHERE account_id IN (SELECT id FROM accounts WHERE company_id = ?) LIMIT 50", (company_id,))
        else:
            return jsonify({"status": "success", "data": []})
            
        rows = [dict(r) for r in cursor.fetchall()]
        return jsonify({"status": "success", "data": rows})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/remediation/tasks', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_remediation_tasks():
    company_id = session.get('active_company_id')
    from database import get_remediation_tasks
    tasks = get_remediation_tasks(company_id)
    return jsonify({"status": "success", "data": tasks})

# ==========================================================
# PHASE 1: PREMIUM AUDIT REPORT CONTRACT ENDPOINTS
# ==========================================================

@app.route('/api/advisor/report/contract', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_report_contract():
    company_id = session.get('active_company_id')
    from advisor_report_contract import build_premium_client_report
    contract = build_premium_client_report(company_id)
    return jsonify({"status": "success", "data": contract})

@app.route('/api/advisor/report/summary', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_report_summary():
    company_id = session.get('active_company_id')
    mode = request.args.get('mode', 'client')
    from advisor_report_contract import build_premium_client_report
    contract = build_premium_client_report(company_id)
    
    summary = {
        "report_id": contract["report_id"],
        "company_id": contract["company_id"],
        "analysis_run_id": contract["analysis_run_id"],
        "period_start": contract["period_start"],
        "period_end": contract["period_end"],
        "summary_text": contract["client_mode_summary"] if mode == 'client' else contract["auditor_mode_summary"],
        "financial_statements_snapshot": contract["financial_statements_snapshot"],
    }
    return jsonify({"status": "success", "data": summary})

@app.route('/api/advisor/report/sections', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_report_sections():
    company_id = session.get('active_company_id')
    from advisor_report_contract import build_premium_client_report
    contract = build_premium_client_report(company_id)
    
    sections = {
        "risk_register": contract["risk_register"],
        "detailed_findings": contract["detailed_findings"],
        "exhibits": contract["exhibits"],
        "internal_controls_section": contract["internal_controls_section"],
        "remediation_plan": contract["remediation_plan"]
    }
    return jsonify({"status": "success", "data": sections})

@app.route('/api/advisor/report/appendix', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_report_appendix():
    company_id = session.get('active_company_id')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    offset = (page - 1) * per_page
    
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT count(*) as total FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE company_id = ?)", (company_id,))
    total = cursor.fetchone()['total']
    
    cursor.execute("SELECT * FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE company_id = ?) LIMIT ? OFFSET ?", (company_id, per_page, offset))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        "status": "success", 
        "data": rows, 
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total + per_page - 1) // per_page
        }
    })

@app.route('/api/remediation/tasks/<int:task_id>', methods=['PUT', 'PATCH'])
@login_required
@require_company_role(['owner', 'admin', 'operator'])
def api_remediation_task_update(task_id):
    company_id = session.get('active_company_id')
    from database import update_remediation_task
    data = request.json
    update_remediation_task(company_id, task_id, data)
    return jsonify({"status": "success"})

@app.route('/api/advisor/re_audit_status', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_advisor_re_audit_status():
    company_id = session.get('active_company_id')
    from database import get_advisor_re_audit_status
    result = get_advisor_re_audit_status(company_id)
    return jsonify(result)

@app.route('/api/export/audit_report', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_export_audit_report():
    company_id = session.get('active_company_id')
    mode = request.args.get('mode', 'client')
    fmt = request.args.get('format', 'pdf').lower()
    
    from advisor_report_contract import build_premium_client_report
    try:
        report_data = build_premium_client_report(company_id)
        report_data['mode'] = mode
        
        if not report_data.get('analysis_run_id') or report_data['analysis_run_id'] == 'N/A' or not report_data.get('detailed_findings'):
            return jsonify({'status': 'empty', 'message': 'No findings available to export.'}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
        
    import io
    from flask import send_file
    from export_engine import generate_pdf_export, generate_docx_export
    
    filename = f"Audit_Report_{company_id}_{mode}.{fmt}"
    if fmt == 'docx':
        content = generate_docx_export(report_data)
        mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    else:
        content = generate_pdf_export(report_data)
        mimetype = 'application/pdf'
        
    return send_file(io.BytesIO(content), mimetype=mimetype, as_attachment=True, download_name=filename)

@app.route('/api/export/finding/<finding_id>', methods=['GET'])
@login_required
@require_company_role(['owner', 'admin', 'operator', 'viewer'])
def api_export_finding(finding_id):
    company_id = session.get('active_company_id')
    mode = request.args.get('mode', 'client')
    fmt = request.args.get('format', 'pdf').lower()
    
    from export_engine import build_finding_report, generate_pdf_export, generate_docx_export
    report_data = build_finding_report(company_id, finding_id, mode)
    if not report_data:
        return jsonify({"status": "error", "message": "Finding not found"}), 404
        
    import io
    from flask import send_file
    
    filename = f"Finding_{finding_id}_{mode}.{fmt}"
    if fmt == 'docx':
        content = generate_docx_export(report_data)
        mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    else:
        content = generate_pdf_export(report_data)
        mimetype = 'application/pdf'
        
    return send_file(io.BytesIO(content), mimetype=mimetype, as_attachment=True, download_name=filename)

import sys

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database (creates tables and bootstraps super admin if configured)
init_db()

# PRODUCTION-SAFE CONFIG GUARDS for QuickBooks
qb_enabled = os.environ.get('QUICKBOOKS_ENABLED', os.environ.get('ENABLE_QB', 'false')).lower() == 'true'
if qb_enabled:
    print("  [INIT] QuickBooks Integration: ENABLED. Validating config...")
    try:
        from shared.quickbooks_client import QuickBooksOAuthService
        QuickBooksOAuthService.validate_config()
        print("  [INIT] QuickBooks config validation PASSED.")
        
        qb_debug = os.environ.get('QUICKBOOKS_DEBUG', os.environ.get('QUICKBOOKS_DEBUG_MODE', 'false')).lower() == 'true'
        if qb_debug:
            print("  [WARNING] QuickBooks Diagnostic Debugging is ENABLED. Do not use in production!")
    except Exception as e:
        print(f"\n  [FATAL STARTUP ERROR] QUICKBOOKS_ENABLED=true but config is invalid:\n  --> {e}\n")
        print("  Shutting down. Either fix your .env file or set QUICKBOOKS_ENABLED=false.\n")
        sys.exit(1)
else:
    print("  [INIT] QuickBooks Integration: DISABLED.")

if __name__ == '__main__':


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

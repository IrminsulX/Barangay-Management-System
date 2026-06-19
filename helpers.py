import re
import time
import sqlite3
import secrets
from datetime import date, datetime
from functools import wraps
from flask import g, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from config import DATABASE, ADMIN_ROLES

# ── Database Helpers ──────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query(sql, params=None, one=False):
    cur = get_db().execute(sql, params or [])
    if sql.strip().upper().startswith('SELECT'):
        return cur.fetchone() if one else cur.fetchall()
    get_db().commit()
    return cur.lastrowid

def dict_row(row):
    if row is None:
        return None
    return dict(row)

def compute_age(birthdate_str):
    if not birthdate_str:
        return 0
    parts = birthdate_str.split('-')
    bd = date(int(parts[0]), int(parts[1]), int(parts[2]))
    today = date.today()
    age = today.year - bd.year - ((today.month, today.day) < (bd.month, bd.day))
    return age

# ── Rate Limiter (Login) ──────────────────────────────────────────

_login_attempts = {}

def _clean_attempts():
    now = time.time()
    expired = [ip for ip, data in _login_attempts.items()
               if data.get('blocked_until', 0) < now and now - data.get('first_attempt', 0) > 1800]
    for ip in expired:
        del _login_attempts[ip]

def check_rate_limit(ip):
    _clean_attempts()
    now = time.time()
    data = _login_attempts.get(ip)
    if data and data.get('blocked_until', 0) > now:
        remaining = int(data['blocked_until'] - now)
        return False, f'Too many attempts. Try again in {remaining // 60}m {remaining % 60}s.'
    return True, None

def record_attempt(ip, success):
    now = time.time()
    if success:
        _login_attempts.pop(ip, None)
        return
    data = _login_attempts.get(ip)
    if data is None:
        _login_attempts[ip] = {'count': 1, 'first_attempt': now, 'blocked_until': 0}
    else:
        data['count'] += 1
        if data['count'] > 5:
            data['blocked_until'] = now + 900
        data['first_attempt'] = now

# ── Password Validation ───────────────────────────────────────────

def validate_password(password):
    if not password or len(password) < 8:
        return False, 'Password must be at least 8 characters.'
    if not re.search(r'[A-Za-z]', password):
        return False, 'Password must contain at least one letter.'
    if not re.search(r'[0-9]', password):
        return False, 'Password must contain at least one number.'
    return True, None

# ── CSRF Protection ──────────────────────────────────────────────

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def csrf_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            token = request.headers.get('X-CSRF-Token') or request.headers.get('X-CSRF-TOKEN')
            if not token or token != session.get('csrf_token'):
                return jsonify({'error': 'Invalid or missing CSRF token'}), 403
        return f(*args, **kwargs)
    return decorated

def csrf_skip(f):
    return f

# ── Activity Logging ──────────────────────────────────────────────

def log_activity(action, entity_type, entity_id=None, details=None):
    username = session.get('username', 'system')
    user_id = session.get('user_id')
    try:
        query(
            "INSERT INTO activity_log (user_id, username, action, entity_type, entity_id, details) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [user_id, username, action, entity_type, entity_id, details]
        )
    except Exception:
        pass

# ── Auth Decorators ───────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        if session.get('role') not in ADMIN_ROLES:
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

# ── File Upload ───────────────────────────────────────────────────

def allowed_file(filename):
    from config import ALLOWED_EXTENSIONS
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ── Notifications ─────────────────────────────────────────────────

def notify(user_id, title, message, type='info', link=None):
    try:
        query(
            "INSERT INTO notifications (user_id, title, message, type, link) VALUES (?, ?, ?, ?, ?)",
            [user_id, title, message, type, link]
        )
    except Exception:
        pass

# ── Two-Factor Authentication ──────────────────────────────────────

_otp_store = {}

def send_otp_email(email, code):
    print(f"[OTP] To: {email}, Code: {code}")
    return True

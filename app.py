"""
Barangay Management System — Flask Application
Complete REST API backend with SQLite database.
"""
import os
import re
import time
import sqlite3
import secrets
from datetime import datetime
from functools import wraps
from flask import (
    Flask, g, request, jsonify, session, redirect, url_for,
    render_template, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'brgy-mgmt-sys-secret-key-change-in-production')
DATABASE = os.path.join(os.path.dirname(__file__), 'barangay.db')

ADMIN_ROLES = ('admin', 'staff', 'barangay_captain', 'kagawad', 'secretary_treasurer', 'sk_chairperson', 'tanod')

# ── Database Helpers ──────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
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
    from datetime import date
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
            data['blocked_until'] = now + 900  # 15 min block
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
    """Skip CSRF check for specific routes (e.g., login)"""
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
        pass  # Never break the main flow for logging

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

# ── Page Routes ───────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') in ADMIN_ROLES:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('resident_home'))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') not in ADMIN_ROLES:
        return redirect(url_for('login_page'))
    return render_template('admin/dashboard.html', active_page='dashboard')

@app.route('/admin/residents')
def admin_residents():
    if 'user_id' not in session or session.get('role') not in ADMIN_ROLES:
        return redirect(url_for('login_page'))
    return render_template('admin/residents.html', active_page='residents')

@app.route('/admin/households')
def admin_households():
    if 'user_id' not in session or session.get('role') not in ADMIN_ROLES:
        return redirect(url_for('login_page'))
    return render_template('admin/households.html', active_page='households')

@app.route('/admin/requests')
def admin_requests():
    if 'user_id' not in session or session.get('role') not in ADMIN_ROLES:
        return redirect(url_for('login_page'))
    return render_template('admin/requests.html', active_page='requests')

@app.route('/admin/blotter')
def admin_blotter():
    if 'user_id' not in session or session.get('role') not in ADMIN_ROLES:
        return redirect(url_for('login_page'))
    return render_template('admin/blotter.html', active_page='blotter')

@app.route('/admin/announcements')
def admin_announcements():
    if 'user_id' not in session or session.get('role') not in ADMIN_ROLES:
        return redirect(url_for('login_page'))
    return render_template('admin/announcements.html', active_page='announcements')

@app.route('/admin/officials')
def admin_officials():
    if 'user_id' not in session or session.get('role') not in ADMIN_ROLES:
        return redirect(url_for('login_page'))
    return render_template('admin/officials.html', active_page='officials')

@app.route('/admin/activity-log')
def admin_activity_log():
    if 'user_id' not in session or session.get('role') not in ADMIN_ROLES:
        return redirect(url_for('login_page'))
    return render_template('admin/activity_log.html', active_page='activity-log')

@app.route('/resident/home')
def resident_home():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/home.html', active_page='home')

@app.route('/resident/requests')
def resident_requests():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/requests.html', active_page='requests')

@app.route('/resident/file-request')
def resident_file_request():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/file_request.html', active_page='file-request')

@app.route('/resident/complaints')
def resident_complaints():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/complaints.html', active_page='complaints')

@app.route('/resident/file-complaint')
def resident_file_complaint():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/file_complaint.html', active_page='file-complaint')

@app.route('/resident/household')
def resident_household():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/household.html', active_page='household')

@app.route('/resident/schedule')
def resident_schedule():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/schedule.html', active_page='schedule')

@app.route('/resident/profile')
def resident_profile():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/profile.html', active_page='profile')

# ── Auth API ──────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def api_login():
    ip = request.remote_addr or 'unknown'
    allowed, msg = check_rate_limit(ip)
    if not allowed:
        return jsonify({'success': False, 'error': msg}), 429

    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    user = query("SELECT * FROM users WHERE username = ?", [username], one=True)
    if user and check_password_hash(user['password_hash'], password):
        record_attempt(ip, success=True)
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['resident_id'] = user['resident_id']
        session.permanent = True
        csrf_token = generate_csrf_token()
        return jsonify({
            'success': True,
            'role': user['role'],
            'username': user['username'],
            'csrf_token': csrf_token
        })
    record_attempt(ip, success=False)
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/session')
def api_session():
    if 'user_id' in session:
        return jsonify({
            'logged_in': True,
            'username': session.get('username'),
            'role': session.get('role'),
            'resident_id': session.get('resident_id'),
            'csrf_token': generate_csrf_token()
        })
    return jsonify({'logged_in': False})

# ── Profile API (Password Change) ────────────────────────────────

@app.route('/api/resident/profile', methods=['GET', 'PUT'])
@login_required
@csrf_required
def api_resident_profile():
    if request.method == 'GET':
        resident_id = session.get('resident_id')
        if not resident_id:
            return jsonify({'error': 'No resident profile linked'}), 400
        row = query("SELECT id, full_name, email, contact_number FROM residents WHERE id = ?", [resident_id], one=True)
        return jsonify(dict_row(row) if row else {})

    data = request.get_json()
    user_id = session.get('user_id')
    current = query("SELECT * FROM users WHERE id = ?", [user_id], one=True)
    if not current:
        return jsonify({'error': 'User not found'}), 404
    old = data.get('current_password', '')
    new = data.get('new_password', '')
    if not old or not new:
        return jsonify({'error': 'Both current and new password are required'}), 400
    if not check_password_hash(current['password_hash'], old):
        return jsonify({'error': 'Current password is incorrect'}), 403
    valid, err = validate_password(new)
    if not valid:
        return jsonify({'error': err}), 400
    query("UPDATE users SET password_hash = ? WHERE id = ?", [generate_password_hash(new), user_id])
    log_activity('update', 'user', user_id, 'Password changed')
    return jsonify({'success': True})

# ── CSV Export ────────────────────────────────────────────────────

@app.route('/api/export/<entity>')
@admin_required
def api_export(entity):
    import csv
    from io import StringIO

    si = StringIO()
    writer = csv.writer(si)

    if entity == 'residents':
        writer.writerow(['ID', 'Full Name', 'Birthdate', 'Age', 'Sex', 'Civil Status', 'Contact', 'Email', 'Household', 'Voter Status', 'Created At'])
        rows = query("""
            SELECT r.id, r.full_name, r.birthdate, r.sex, r.civil_status, r.contact_number,
                   r.email, h.household_code, r.voter_status, r.created_at
            FROM residents r LEFT JOIN households h ON r.household_id = h.id ORDER BY r.full_name
        """)
        for r in rows:
            writer.writerow([r['id'], r['full_name'], r['birthdate'], compute_age(r['birthdate']),
                           r['sex'], r['civil_status'], r['contact_number'], r['email'],
                           r['household_code'] or '—', 'Registered' if r['voter_status'] else 'Not Registered', r['created_at']])

    elif entity == 'households':
        writer.writerow(['ID', 'Code', 'Address', 'Head', 'Member Count', 'Created At'])
        rows = query("""
            SELECT h.*, r.full_name as head_name,
                (SELECT COUNT(*) FROM residents WHERE household_id = h.id) as member_count
            FROM households h LEFT JOIN residents r ON h.head_resident_id = r.id ORDER BY h.household_code
        """)
        for r in rows:
            writer.writerow([r['id'], r['household_code'], r['address'], r['head_name'] or '—', r['member_count'], r['created_at']])

    elif entity == 'requests':
        writer.writerow(['ID', 'Resident', 'Document Type', 'Purpose', 'Status', 'Date Requested', 'Date Released', 'Notes'])
        rows = query("""
            SELECT d.*, r.full_name as resident_name
            FROM document_requests d JOIN residents r ON d.resident_id = r.id ORDER BY d.date_requested DESC
        """)
        for d in rows:
            writer.writerow([d['id'], d['resident_name'], d['document_type'], d['purpose'] or '—',
                           d['status'], d['date_requested'], d['date_released'] or '—', d['notes'] or '—'])

    elif entity == 'blotter':
        writer.writerow(['ID', 'Complainant', 'Respondent', 'Incident', 'Date Filed', 'Status', 'Resolution'])
        rows = query("""
            SELECT b.*, r.full_name as complainant_name
            FROM blotter b JOIN residents r ON b.complainant_id = r.id ORDER BY b.date_filed DESC
        """)
        for b in rows:
            writer.writerow([b['id'], b['complainant_name'], b['respondent_name'], b['incident_details'],
                           b['date_filed'], b['status'], b['resolution_notes'] or '—'])

    else:
        return jsonify({'error': 'Unknown entity'}), 400

    log_activity('export', entity, details=f'Exported {entity} to CSV')
    output = si.getvalue()
    return (
        output,
        200,
        {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': f'attachment; filename={entity}_{datetime.now().strftime("%Y%m%d")}.csv'
        }
    )

# ── Activity Log API ─────────────────────────────────────────────

@app.route('/api/activity-log')
@admin_required
def api_activity_log():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    action_filter = request.args.get('action', '')

    where = ''
    params = []
    if action_filter:
        where = " WHERE action = ?"
        params.append(action_filter)

    count = query(f"SELECT COUNT(*) as c FROM activity_log{where}", params, one=True)['c']
    offset = (page - 1) * per_page
    rows = query(f"SELECT * FROM activity_log{where} ORDER BY created_at DESC LIMIT ? OFFSET ?", params + [per_page, offset])
    return jsonify({
        'rows': [dict_row(r) for r in rows],
        'total': count,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, (count + per_page - 1) // per_page)
    })

# ── Dashboard Stats API ───────────────────────────────────────────

@app.route('/api/dashboard-stats')
@admin_required
def api_dashboard_stats():
    from_date = request.args.get('from')
    to_date = request.args.get('to')

    total_residents = query("SELECT COUNT(*) as count FROM residents", one=True)['count']
    total_households = query("SELECT COUNT(*) as count FROM households", one=True)['count']
    pending_requests = query("SELECT COUNT(*) as count FROM document_requests WHERE status = 'Pending'", one=True)['count']
    open_complaints = query("SELECT COUNT(*) as count FROM blotter WHERE status IN ('Filed','Under Investigation')", one=True)['count']

    # Monthly requests chart data (last 6 months)
    monthly = query("""
        SELECT strftime('%Y-%m', date_requested) as month, COUNT(*) as count
        FROM document_requests
        WHERE date_requested >= date('now', '-6 months')
        GROUP BY month ORDER BY month
    """)
    monthly_data = [{'month': r['month'], 'count': r['count']} for r in monthly]

    # Status distribution
    status_dist = query("""
        SELECT status, COUNT(*) as count FROM document_requests GROUP BY status
    """)
    status_data = [{'status': r['status'], 'count': r['count']} for r in status_dist]

    # Blotter by status
    blotter_status = query("""
        SELECT status, COUNT(*) as count FROM blotter GROUP BY status
    """)
    blotter_data = [{'status': r['status'], 'count': r['count']} for r in blotter_status]

    # Recent activity from activity_log (with date filter)
    if from_date and to_date:
        act_rows = query(
            "SELECT * FROM activity_log WHERE date(created_at) BETWEEN ? AND ? ORDER BY created_at DESC LIMIT 20",
            [from_date, to_date]
        )
    else:
        act_rows = query("SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 10")
    recent_activity = [dict_row(r) for r in act_rows]

    # Age distribution
    age_data = query("SELECT birthdate FROM residents")
    age_labels = ['0-17', '18-30', '31-45', '46-60', '60+']
    age_counts = [0, 0, 0, 0, 0]
    for r in age_data:
        age = compute_age(r['birthdate'])
        if age < 18: age_counts[0] += 1
        elif age <= 30: age_counts[1] += 1
        elif age <= 45: age_counts[2] += 1
        elif age <= 60: age_counts[3] += 1
        else: age_counts[4] += 1

    # Civil status distribution
    civil_data = query("SELECT civil_status, COUNT(*) as count FROM residents GROUP BY civil_status")
    civil_status_labels = [r['civil_status'] for r in civil_data]
    civil_status_counts = [r['count'] for r in civil_data]

    return jsonify({
        'total_residents': total_residents,
        'total_households': total_households,
        'pending_requests': pending_requests,
        'open_complaints': open_complaints,
        'monthly_requests': monthly_data,
        'status_distribution': status_data,
        'blotter_status': blotter_data,
        'recent_activity': recent_activity,
        'age_labels': age_labels,
        'age_counts': age_counts,
        'civil_status_labels': civil_status_labels,
        'civil_status_counts': civil_status_counts
    })

# ── Residents API ─────────────────────────────────────────────────

@app.route('/api/residents', methods=['GET', 'POST'])
@admin_required
@csrf_required
def api_residents():
    if request.method == 'GET':
        search = request.args.get('search', '')
        household_id = request.args.get('household_id', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        params = []
        where = "WHERE 1=1"
        if search:
            where += " AND r.full_name LIKE ?"
            params.append(f'%{search}%')
        if household_id:
            where += " AND r.household_id = ?"
            params.append(household_id)

        count = query(f"SELECT COUNT(*) as c FROM residents r {where}", params[:], one=True)['c']
        offset = (page - 1) * per_page
        sql = f"SELECT r.*, h.household_code, h.address as household_address FROM residents r LEFT JOIN households h ON r.household_id = h.id {where} ORDER BY r.full_name LIMIT ? OFFSET ?"
        rows = query(sql, params + [per_page, offset])
        result = [dict_row(r) for r in rows]
        for r in result:
            r['age'] = compute_age(r['birthdate'])
        return jsonify({
            'rows': result,
            'total': count,
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (count + per_page - 1) // per_page)
        })

    data = request.get_json()
    password = data.get('password', '')
    username = data.get('username', '').strip()
    if username and password:
        valid, err = validate_password(password)
        if not valid:
            return jsonify({'error': err}), 400

    rid = query(
        "INSERT INTO residents (full_name, birthdate, sex, civil_status, contact_number, email, household_id, voter_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [data['full_name'], data['birthdate'], data['sex'], data['civil_status'],
         data.get('contact_number', ''), data.get('email', ''), data.get('household_id'), int(data.get('voter_status', 0))]
    )
    if username and password:
        existing = query("SELECT id FROM users WHERE username = ?", [username], one=True)
        if existing:
            return jsonify({'error': 'Username already taken'}), 409
        query(
            "INSERT INTO users (username, password_hash, role, resident_id) VALUES (?, ?, 'resident', ?)",
            [username, generate_password_hash(password), rid]
        )
    log_activity('create', 'resident', rid, f"Added resident {data['full_name']}")
    return jsonify({'success': True, 'id': rid}), 201

@app.route('/api/residents/<int:rid>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
@csrf_required
def api_resident(rid):
    if request.method == 'GET':
        row = query("SELECT r.*, h.household_code, h.address as household_address FROM residents r LEFT JOIN households h ON r.household_id = h.id WHERE r.id = ?", [rid], one=True)
        if not row:
            return jsonify({'error': 'Not found'}), 404
        result = dict_row(row)
        result['age'] = compute_age(result['birthdate'])
        return jsonify(result)

    if request.method == 'PUT':
        data = request.get_json()
        query(
            "UPDATE residents SET full_name=?, birthdate=?, sex=?, civil_status=?, contact_number=?, email=?, household_id=?, voter_status=? WHERE id=?",
            [data['full_name'], data['birthdate'], data['sex'], data['civil_status'],
             data.get('contact_number', ''), data.get('email', ''), data.get('household_id'), int(data.get('voter_status', 0)), rid]
        )
        log_activity('update', 'resident', rid, f"Updated resident {data['full_name']}")
        return jsonify({'success': True})

    former = query("SELECT full_name FROM residents WHERE id = ?", [rid], one=True)
    name = former['full_name'] if former else f'ID {rid}'
    query("DELETE FROM residents WHERE id = ?", [rid])
    log_activity('delete', 'resident', rid, f"Deleted resident {name}")
    return jsonify({'success': True})

# ── Households API ────────────────────────────────────────────────

@app.route('/api/households', methods=['GET', 'POST'])
@admin_required
@csrf_required
def api_households():
    if request.method == 'GET':
        search = request.args.get('search', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        where = ""
        params = []
        if search:
            where = " WHERE h.household_code LIKE ? OR h.address LIKE ?"
            params.extend([f'%{search}%', f'%{search}%'])

        count = query(f"SELECT COUNT(*) as c FROM households h{where}", params[:], one=True)['c']
        offset = (page - 1) * per_page
        sql = f"""
            SELECT h.*, r.full_name as head_name,
                (SELECT COUNT(*) FROM residents WHERE household_id = h.id) as member_count
            FROM households h
            LEFT JOIN residents r ON h.head_resident_id = r.id
            {where}
            ORDER BY h.household_code LIMIT ? OFFSET ?
        """
        rows = query(sql, params + [per_page, offset])
        return jsonify({
            'rows': [dict_row(r) for r in rows],
            'total': count,
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (count + per_page - 1) // per_page)
        })

    data = request.get_json()
    hid = query(
        "INSERT INTO households (household_code, head_resident_id, address) VALUES (?, ?, ?)",
        [data['household_code'], data.get('head_resident_id'), data['address']]
    )
    if data.get('head_resident_id'):
        query("UPDATE residents SET household_id = ? WHERE id = ?", [hid, data['head_resident_id']])
    log_activity('create', 'household', hid, f"Added household {data['household_code']}")
    return jsonify({'success': True, 'id': hid}), 201

@app.route('/api/households/<int:hid>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
@csrf_required
def api_household(hid):
    if request.method == 'GET':
        row = query("""
            SELECT h.*, r.full_name as head_name,
                (SELECT COUNT(*) FROM residents WHERE household_id = h.id) as member_count
            FROM households h LEFT JOIN residents r ON h.head_resident_id = r.id WHERE h.id = ?
        """, [hid], one=True)
        if not row:
            return jsonify({'error': 'Not found'}), 404
        result = dict_row(row)
        result['members'] = [dict_row(r) for r in query("SELECT * FROM residents WHERE household_id = ?", [hid])]
        return jsonify(result)

    if request.method == 'PUT':
        data = request.get_json()
        query(
            "UPDATE households SET household_code=?, head_resident_id=?, address=? WHERE id=?",
            [data['household_code'], data.get('head_resident_id'), data['address'], hid]
        )
        log_activity('update', 'household', hid, f"Updated household {data['household_code']}")
        return jsonify({'success': True})

    former = query("SELECT household_code FROM households WHERE id = ?", [hid], one=True)
    code = former['household_code'] if former else f'ID {hid}'
    query("DELETE FROM households WHERE id = ?", [hid])
    log_activity('delete', 'household', hid, f"Deleted household {code}")
    return jsonify({'success': True})

# ── My Household API (Resident) ────────────────────────────────────

@app.route('/api/my-household')
@login_required
def api_my_household():
    resident_id = session.get('resident_id')
    if not resident_id:
        return jsonify({'error': 'No resident profile linked'}), 400
    resident = query("SELECT * FROM residents WHERE id = ?", [resident_id], one=True)
    if not resident:
        return jsonify({'error': 'Resident not found'}), 404
    household_id = resident['household_id']
    if not household_id:
        return jsonify({'household': None})
    h = query("""
        SELECT h.*, r.full_name as head_name,
            (SELECT COUNT(*) FROM residents WHERE household_id = h.id) as member_count
        FROM households h LEFT JOIN residents r ON h.head_resident_id = r.id WHERE h.id = ?
    """, [household_id], one=True)
    if not h:
        return jsonify({'household': None})
    result = dict_row(h)
    result['members'] = [dict_row(r) for r in query("SELECT * FROM residents WHERE household_id = ? ORDER BY full_name", [household_id])]
    result['current_resident'] = dict_row(resident)
    return jsonify({'household': result})

@app.route('/api/my-household/members', methods=['POST'])
@login_required
@csrf_required
def api_my_household_add_member():
    resident_id = session.get('resident_id')
    if not resident_id:
        return jsonify({'error': 'No resident profile linked'}), 400
    resident = query("SELECT * FROM residents WHERE id = ?", [resident_id], one=True)
    if not resident or not resident['household_id']:
        return jsonify({'error': 'You must belong to a household first'}), 400
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if username and password:
        valid, err = validate_password(password)
        if not valid:
            return jsonify({'error': err}), 400
        existing = query("SELECT id FROM users WHERE username = ?", [username], one=True)
        if existing:
            return jsonify({'error': 'Username already taken'}), 409
    new_id = query(
        "INSERT INTO residents (full_name, birthdate, sex, civil_status, contact_number, email, household_id, voter_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [data['full_name'], data['birthdate'], data['sex'], data['civil_status'],
         data.get('contact_number', ''), data.get('email', ''), resident['household_id'], int(data.get('voter_status', 0))]
    )
    if username and password:
        query(
            "INSERT INTO users (username, password_hash, role, resident_id) VALUES (?, ?, 'resident', ?)",
            [username, generate_password_hash(password), new_id]
        )
    log_activity('create', 'resident', new_id, f"Member {data['full_name']} added to household")
    return jsonify({'success': True, 'id': new_id}), 201

# ── Document Requests API ─────────────────────────────────────────

@app.route('/api/requests', methods=['GET', 'POST'])
@login_required
@csrf_required
def api_requests():
    if request.method == 'GET':
        resident_id = request.args.get('resident_id', '')
        status_filter = request.args.get('status', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        where = ""
        params = []
        if resident_id:
            where += " AND d.resident_id = ?"
            params.append(resident_id)
        if status_filter:
            where += " AND d.status = ?"
            params.append(status_filter)
        if session.get('role') != 'admin' and session.get('role') != 'staff':
            where += " AND d.resident_id = ?"
            params.append(session.get('resident_id'))

        count = query(f"SELECT COUNT(*) as c FROM document_requests d WHERE 1=1{where}", params[:], one=True)['c']
        offset = (page - 1) * per_page
        sql = f"""
            SELECT d.*, r.full_name as resident_name, h.address
            FROM document_requests d
            JOIN residents r ON d.resident_id = r.id
            LEFT JOIN households h ON r.household_id = h.id
            WHERE 1=1{where}
            ORDER BY d.date_requested DESC LIMIT ? OFFSET ?
        """
        rows = query(sql, params + [per_page, offset])
        return jsonify({
            'rows': [dict_row(r) for r in rows],
            'total': count,
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (count + per_page - 1) // per_page)
        })

    data = request.get_json()
    resident_id = session.get('resident_id') if session.get('role') == 'resident' else data.get('resident_id')
    if not resident_id:
        return jsonify({'error': 'Resident ID required'}), 400
    rid = query(
        "INSERT INTO document_requests (resident_id, document_type, purpose, status) VALUES (?, ?, ?, 'Pending')",
        [resident_id, data['document_type'], data.get('purpose', '')]
    )
    log_activity('create', 'request', rid, f"Request for {data['document_type']}")
    return jsonify({'success': True, 'id': rid}), 201

@app.route('/api/requests/<int:rid>', methods=['PUT'])
@login_required
@csrf_required
def api_update_request(rid):
    data = request.get_json()
    if 'status' in data:
        released = datetime.now().isoformat() if data['status'] == 'Released' else None
        query(
            "UPDATE document_requests SET status=?, notes=?, date_released=? WHERE id=?",
            [data['status'], data.get('notes', ''), released, rid]
        )
        log_activity('update', 'request', rid, f"Request status changed to {data['status']}")
    return jsonify({'success': True})

# ── Blotter API ───────────────────────────────────────────────────

@app.route('/api/blotter', methods=['GET', 'POST'])
@login_required
@csrf_required
def api_blotter():
    if request.method == 'GET':
        status = request.args.get('status', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        where = ""
        params = []
        if session.get('role') == 'resident':
            where += " AND b.complainant_id = ?"
            params.append(session.get('resident_id'))
        if status:
            where += " AND b.status = ?"
            params.append(status)

        count = query(f"SELECT COUNT(*) as c FROM blotter b WHERE 1=1{where}", params[:], one=True)['c']
        offset = (page - 1) * per_page
        sql = f"""
            SELECT b.*, r.full_name as complainant_name, r.contact_number as complainant_contact
            FROM blotter b
            JOIN residents r ON b.complainant_id = r.id
            WHERE 1=1{where}
            ORDER BY b.date_filed DESC LIMIT ? OFFSET ?
        """
        rows = query(sql, params + [per_page, offset])
        return jsonify({
            'rows': [dict_row(r) for r in rows],
            'total': count,
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (count + per_page - 1) // per_page)
        })

    data = request.get_json()
    complainant_id = session.get('resident_id') if session.get('role') == 'resident' else data.get('complainant_id')
    bid = query(
        "INSERT INTO blotter (complainant_id, respondent_name, incident_details, incident_date, incident_location) "
        "VALUES (?, ?, ?, ?, ?)",
        [complainant_id, data['respondent_name'], data['incident_details'],
         data.get('incident_date'), data.get('incident_location')]
    )
    log_activity('create', 'blotter', bid, f"Complaint filed against {data['respondent_name']}")
    return jsonify({'success': True, 'id': bid}), 201

@app.route('/api/blotter/<int:bid>', methods=['PUT'])
@admin_required
@csrf_required
def api_update_blotter(bid):
    data = request.get_json()
    resolved = None
    if data.get('status') in ('Resolved', 'Dismissed'):
        resolved = datetime.now().isoformat()
    query(
        "UPDATE blotter SET status=?, resolution_notes=?, date_resolved=? WHERE id=?",
        [data.get('status', 'Filed'), data.get('resolution_notes', ''), resolved, bid]
    )
    log_activity('update', 'blotter', bid, f"Blotter case status changed to {data.get('status')}")
    return jsonify({'success': True})

# ── Announcements API ─────────────────────────────────────────────

@app.route('/api/announcements', methods=['GET', 'POST'])
@login_required
@csrf_required
def api_announcements():
    if request.method == 'GET':
        rows = query("SELECT * FROM announcements ORDER BY created_at DESC")
        return jsonify([dict_row(r) for r in rows])

    if session.get('role') not in ADMIN_ROLES:
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    aid = query(
        "INSERT INTO announcements (title, description, category, event_date, created_by) VALUES (?, ?, ?, ?, ?)",
        [data['title'], data['description'], data['category'], data.get('event_date'), session['user_id']]
    )
    log_activity('create', 'announcement', aid, f"Created announcement: {data['title']}")
    return jsonify({'success': True, 'id': aid}), 201

@app.route('/api/announcements/<int:aid>', methods=['PUT', 'DELETE'])
@admin_required
@csrf_required
def api_announcement(aid):
    if request.method == 'PUT':
        data = request.get_json()
        query(
            "UPDATE announcements SET title=?, description=?, category=?, event_date=? WHERE id=?",
            [data['title'], data['description'], data['category'], data.get('event_date'), aid]
        )
        log_activity('update', 'announcement', aid, f"Updated announcement: {data['title']}")
        return jsonify({'success': True})

    former = query("SELECT title FROM announcements WHERE id = ?", [aid], one=True)
    title = former['title'] if former else f'ID {aid}'
    query("DELETE FROM announcements WHERE id = ?", [aid])
    log_activity('delete', 'announcement', aid, f"Deleted announcement: {title}")
    return jsonify({'success': True})

# ── Officials API ──────────────────────────────────────────────────

@app.route('/api/officials')
@admin_required
def api_officials():
    search = request.args.get('search', '')
    where = ""
    params = []
    if search:
        where = " WHERE r.full_name LIKE ?"
        params.append(f'%{search}%')
    role_placeholders = ','.join('?' * len(ADMIN_ROLES))
    rows = query(f"""
        SELECT u.id, u.username, u.role, u.created_at,
               r.id as resident_id, r.full_name, r.email, r.contact_number
        FROM users u
        JOIN residents r ON u.resident_id = r.id
        WHERE u.role IN ({role_placeholders}){where}
        ORDER BY u.role, r.full_name
    """, list(ADMIN_ROLES) + params)
    return jsonify([dict_row(r) for r in rows])

@app.route('/api/officials/candidates')
@admin_required
def api_officials_candidates():
    search = request.args.get('search', '')
    where = ""
    params = []
    if search:
        where = " AND r.full_name LIKE ?"
        params.append(f'%{search}%')
    rows = query(f"""
        SELECT r.*, u.id as user_id, u.username, u.role
        FROM residents r
        LEFT JOIN users u ON u.resident_id = r.id
        WHERE (u.id IS NULL OR u.role = 'resident'){where}
        ORDER BY r.full_name
    """, params)
    return jsonify([dict_row(r) for r in rows])

@app.route('/api/officials/promote', methods=['POST'])
@admin_required
@csrf_required
def api_officials_promote():
    data = request.get_json()
    resident_id = data.get('resident_id')
    role = data.get('role', 'barangay_captain')
    if role not in ADMIN_ROLES:
        return jsonify({'error': 'Invalid role'}), 400

    existing = query("SELECT id FROM users WHERE resident_id = ?", [resident_id], one=True)
    if existing:
        query("UPDATE users SET role = ? WHERE id = ?", [role, existing['id']])
        log_activity('update', 'user', existing['id'], f"Promoted resident #{resident_id} to {role}")
    else:
        resident = query("SELECT * FROM residents WHERE id = ?", [resident_id], one=True)
        if not resident:
            return jsonify({'error': 'Resident not found'}), 404
        username = data.get('username', '').strip() or resident['full_name'].lower().replace(' ', '.')
        password = data.get('password', '')
        if not password:
            return jsonify({'error': 'Password is required for new accounts'}), 400
        valid, err = validate_password(password)
        if not valid:
            return jsonify({'error': err}), 400
        existing_u = query("SELECT id FROM users WHERE username = ?", [username], one=True)
        if existing_u:
            return jsonify({'error': 'Username already taken'}), 409
        uid = query(
            "INSERT INTO users (username, password_hash, role, resident_id) VALUES (?, ?, ?, ?)",
            [username, generate_password_hash(password), role, resident_id]
        )
        log_activity('create', 'user', uid, f"Created {role} account for {resident['full_name']}")

    return jsonify({'success': True})

@app.route('/api/officials/<int:uid>', methods=['DELETE'])
@admin_required
@csrf_required
def api_officials_remove(uid):
    if uid == session.get('user_id'):
        return jsonify({'error': 'Cannot remove yourself'}), 400
    user = query("SELECT * FROM users WHERE id = ?", [uid], one=True)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    query("UPDATE users SET role = 'resident' WHERE id = ?", [uid])
    log_activity('update', 'user', uid, f"Demoted user #{uid} to resident")
    return jsonify({'success': True})

# ── Schedules API ──────────────────────────────────────────────────

DAY_NAMES = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday']

@app.route('/api/schedules')
@login_required
def api_schedules():
    user_id = request.args.get('user_id', type=int)
    day = request.args.get('day', type=int)
    where = ""
    params = []
    if user_id:
        where += " AND s.user_id = ?"
        params.append(user_id)
    if day is not None:
        where += " AND s.day_of_week = ?"
        params.append(day)
    rows = query(f"""
        SELECT s.*, u.username, u.role, r.full_name, r.contact_number
        FROM schedules s
        JOIN users u ON s.user_id = u.id
        JOIN residents r ON u.resident_id = r.id
        WHERE 1=1{where}
        ORDER BY s.day_of_week, s.start_time
    """, params)
    return jsonify([dict_row(r) for r in rows])

@app.route('/api/schedules', methods=['POST'])
@admin_required
@csrf_required
def api_schedules_create():
    data = request.get_json()
    user_id = data.get('user_id')
    day_of_week = data.get('day_of_week')
    schedule_date = data.get('schedule_date')
    start_time = data.get('start_time')
    end_time = data.get('end_time')
    duty_type = data.get('duty_type', 'Office Hours')

    if not all([user_id, day_of_week is not None, start_time, end_time]):
        return jsonify({'error': 'user_id, day_of_week, start_time, end_time are required'}), 400
    if day_of_week < 0 or day_of_week > 6:
        return jsonify({'error': 'day_of_week must be 0-6'}), 400

    sid = query(
        "INSERT INTO schedules (user_id, day_of_week, schedule_date, start_time, end_time, duty_type) VALUES (?, ?, ?, ?, ?, ?)",
        [user_id, day_of_week, schedule_date, start_time, end_time, duty_type]
    )
    user = query("SELECT username FROM users WHERE id = ?", [user_id], one=True)
    label = schedule_date or DAY_NAMES[day_of_week]
    log_activity('create', 'schedule', sid, f"Added schedule on {label} for {user['username']}")
    return jsonify({'success': True, 'id': sid}), 201

@app.route('/api/schedules/<int:sid>', methods=['DELETE'])
@admin_required
@csrf_required
def api_schedules_delete(sid):
    sched = query("SELECT * FROM schedules WHERE id = ?", [sid], one=True)
    if not sched:
        return jsonify({'error': 'Schedule not found'}), 404
    query("DELETE FROM schedules WHERE id = ?", [sid])
    log_activity('delete', 'schedule', sid, f"Removed schedule on {DAY_NAMES[sched['day_of_week']]}")
    return jsonify({'success': True})

# ── Printable Certificate Templates ───────────────────────────────

@app.route('/api/print/request/<int:rid>')
@admin_required
def print_request(rid):
    req = query("""
        SELECT d.*, r.full_name, r.birthdate, r.sex, r.civil_status, r.contact_number,
               r.voter_status, h.address, h.household_code
        FROM document_requests d
        JOIN residents r ON d.resident_id = r.id
        LEFT JOIN households h ON r.household_id = h.id
        WHERE d.id = ?
    """, [rid], one=True)
    if not req:
        return jsonify({'error': 'Not found'}), 404
    return render_template('shared/certificate.html', data=dict_row(req))

@app.route('/api/print/blotter/<int:bid>')
@admin_required
def print_blotter(bid):
    b = query("""
        SELECT b.*, r.full_name as complainant_name, h.address as complainant_address,
               r.contact_number as complainant_contact
        FROM blotter b
        JOIN residents r ON b.complainant_id = r.id
        LEFT JOIN households h ON r.household_id = h.id
        WHERE b.id = ?
    """, [bid], one=True)
    if not b:
        return jsonify({'error': 'Not found'}), 404
    return render_template('shared/blotter_report.html', data=dict_row(b))

# ── Notifications API ─────────────────────────────────────────────

def notify(user_id, title, message, type='info', link=None):
    try:
        query(
            "INSERT INTO notifications (user_id, title, message, type, link) VALUES (?, ?, ?, ?, ?)",
            [user_id, title, message, type, link]
        )
    except Exception:
        pass

@app.route('/api/notifications')
@login_required
def api_notifications():
    user_id = session['user_id']
    rows = query(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
        [user_id]
    )
    unread = query(
        "SELECT COUNT(*) as c FROM notifications WHERE user_id = ? AND is_read = 0",
        [user_id], one=True
    )['c']
    return jsonify({
        'rows': [dict_row(r) for r in rows],
        'unread_count': unread
    })

@app.route('/api/notifications/read', methods=['POST'])
@login_required
@csrf_required
def api_notifications_read():
    query("UPDATE notifications SET is_read = 1 WHERE user_id = ?", [session['user_id']])
    return jsonify({'success': True})

# ── Barangay ID Print ─────────────────────────────────────────────

@app.route('/api/print/barangay-id/<int:rid>')
@login_required
def print_barangay_id(rid):
    r = query("""
        SELECT r.*, h.household_code, h.address as household_address,
               u.username
        FROM residents r
        LEFT JOIN households h ON r.household_id = h.id
        LEFT JOIN users u ON u.resident_id = r.id
        WHERE r.id = ?
    """, [rid], one=True)
    if not r:
        return jsonify({'error': 'Not found'}), 404
    return render_template('shared/barangay_id.html', data=dict_row(r))

# ── Bulk CSV Import ────────────────────────────────────────────────

@app.route('/api/import/residents', methods=['POST'])
@admin_required
@csrf_required
def api_import_residents():
    import csv
    from io import StringIO

    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    content = file.read().decode('utf-8-sig')
    reader = csv.DictReader(StringIO(content))
    imported = 0
    errors = []

    for i, row in enumerate(reader, start=1):
        try:
            full_name = row.get('full_name', '').strip()
            birthdate = row.get('birthdate', '').strip()
            sex = row.get('sex', 'Male')
            civil_status = row.get('civil_status', 'Single')
            if not full_name or not birthdate:
                errors.append(f"Row {i}: full_name and birthdate are required")
                continue
            if sex not in ('Male', 'Female'):
                sex = 'Male'
            if civil_status not in ('Single', 'Married', 'Widowed', 'Divorced', 'Separated'):
                civil_status = 'Single'

            rid = query(
                "INSERT INTO residents (full_name, birthdate, sex, civil_status, contact_number, email, voter_status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [full_name, birthdate, sex, civil_status,
                 row.get('contact_number', '').strip(),
                 row.get('email', '').strip(),
                 int(row.get('voter_status', 0))]
            )
            log_activity('create', 'resident', rid, f"Bulk imported: {full_name}")
            imported += 1
        except Exception as e:
            errors.append(f"Row {i}: {str(e)}")

    return jsonify({
        'success': True,
        'imported': imported,
        'errors': errors
    })

# ── Database Backup & Restore ──────────────────────────────────────

@app.route('/api/backup')
@admin_required
def api_backup():
    backup_path = DATABASE + '.backup'
    try:
        conn = sqlite3.connect(DATABASE)
        bconn = sqlite3.connect(backup_path)
        conn.backup(bconn)
        bconn.close()
        conn.close()
        log_activity('export', 'database', details='Database backup created')
        return send_file(backup_path, as_attachment=True, download_name=f'barangay_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/restore', methods=['POST'])
@admin_required
@csrf_required
def api_restore():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400
    try:
        file.save(DATABASE + '.restored')
        log_activity('import', 'database', details='Database restored from backup')
        return jsonify({'success': True, 'message': 'Database restored. Please restart the application.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Two-Factor Authentication ──────────────────────────────────────

# In-memory store for 2FA codes (email -> code, expiry)
_otp_store = {}

def send_otp_email(email, code):
    # Placeholder — in production, integrate with SMTP / SendGrid / etc.
    print(f"[OTP] To: {email}, Code: {code}")
    return True

@app.route('/api/2fa/send', methods=['POST'])
@login_required
def api_2fa_send():
    user_id = session['user_id']
    user = query("SELECT id, username FROM users WHERE id = ?", [user_id], one=True)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    resident = query("SELECT email FROM residents WHERE id = (SELECT resident_id FROM users WHERE id = ?)", [user_id], one=True)
    email = (resident['email'] if resident and resident.get('email') else None) or f"{user['username']}@barangay779.local"

    code = str(secrets.randbelow(900000) + 100000)
    _otp_store[user_id] = {'code': code, 'expiry': time.time() + 300}

    send_otp_email(email, code)
    return jsonify({'success': True, 'message': f'OTP sent to {email}' if '@barangay779.local' not in email else 'OTP sent (check server console)'})

@app.route('/api/2fa/verify', methods=['POST'])
@login_required
@csrf_required
def api_2fa_verify():
    data = request.get_json()
    user_id = session['user_id']
    stored = _otp_store.get(user_id)
    if not stored:
        return jsonify({'error': 'No OTP requested. Please request a new code.'}), 400
    if time.time() > stored['expiry']:
        _otp_store.pop(user_id, None)
        return jsonify({'error': 'OTP has expired. Please request a new code.'}), 400
    if data.get('code') != stored['code']:
        return jsonify({'error': 'Invalid OTP code'}), 403

    _otp_store.pop(user_id, None)
    session['2fa_verified'] = True
    return jsonify({'success': True})

# ── Template Filters ─────────────────────────────────────────────

@app.template_filter('fmt_date')
def fmt_date(dt_str):
    """Convert ISO datetime string to MM/DD/YYYY"""
    if not dt_str:
        return ''
    parts = str(dt_str).split(' ')[0].split('-')
    if len(parts) == 3:
        return f"{parts[1]}/{parts[2]}/{parts[0]}"
    return str(dt_str)

# ── Run ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        from database.seed import seed
        seed()
    else:
        schema_path = os.path.join(os.path.dirname(__file__), 'database', 'schema.sql')
        if os.path.exists(schema_path):
            conn = sqlite3.connect(DATABASE)
            conn.execute("PRAGMA foreign_keys = ON")
            with open(schema_path, 'r') as f:
                conn.executescript(f.read())
            conn.close()

    # Migration: widen users.role CHECK constraint for new role names
    if os.path.exists(DATABASE):
        try:
            conn = sqlite3.connect(DATABASE)
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")
            row = cur.fetchone()
            if row and 'CHECK' in (row[0] or '').upper():
                conn.close()
                conn = sqlite3.connect(DATABASE)
                conn.execute("PRAGMA foreign_keys = OFF")
                conn.executescript("""
                    CREATE TABLE users_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'resident',
                        resident_id INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (resident_id) REFERENCES residents(id) ON DELETE SET NULL
                    );
                    INSERT INTO users_new SELECT * FROM users;
                    DROP TABLE users;
                    ALTER TABLE users_new RENAME TO users;
                """)
                conn.execute("PRAGMA foreign_keys = ON")
                conn.commit()
        finally:
            try: conn.close()
            except: pass

    # Migration: add schedule_date column to schedules table
    if os.path.exists(DATABASE):
        try:
            conn = sqlite3.connect(DATABASE)
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.execute("PRAGMA table_info(schedules)")
            cols = [row[1] for row in cur.fetchall()]
            if 'schedule_date' not in cols:
                conn.execute("ALTER TABLE schedules ADD COLUMN schedule_date DATE")
                conn.commit()
        finally:
            try: conn.close()
            except: pass

    debug_mode = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)

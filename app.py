"""
Barangay Management System — Flask Application
Complete REST API backend with SQLite database.
"""
import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask, g, request, jsonify, session, redirect, url_for,
    render_template, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'brgy-mgmt-sys-secret-key-change-in-production'
DATABASE = os.path.join(os.path.dirname(__file__), 'barangay.db')

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
        if session.get('role') not in ('admin', 'staff'):
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

# ── Page Routes ───────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') in ('admin', 'staff'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('resident_home'))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') not in ('admin', 'staff'):
        return redirect(url_for('login_page'))
    return render_template('admin/dashboard.html', active_page='dashboard')

@app.route('/admin/residents')
def admin_residents():
    if 'user_id' not in session or session.get('role') not in ('admin', 'staff'):
        return redirect(url_for('login_page'))
    return render_template('admin/residents.html', active_page='residents')

@app.route('/admin/households')
def admin_households():
    if 'user_id' not in session or session.get('role') not in ('admin', 'staff'):
        return redirect(url_for('login_page'))
    return render_template('admin/households.html', active_page='households')

@app.route('/admin/requests')
def admin_requests():
    if 'user_id' not in session or session.get('role') not in ('admin', 'staff'):
        return redirect(url_for('login_page'))
    return render_template('admin/requests.html', active_page='requests')

@app.route('/admin/blotter')
def admin_blotter():
    if 'user_id' not in session or session.get('role') not in ('admin', 'staff'):
        return redirect(url_for('login_page'))
    return render_template('admin/blotter.html', active_page='blotter')

@app.route('/admin/announcements')
def admin_announcements():
    if 'user_id' not in session or session.get('role') not in ('admin', 'staff'):
        return redirect(url_for('login_page'))
    return render_template('admin/announcements.html', active_page='announcements')

@app.route('/resident/home')
def resident_home():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/home.html')

@app.route('/resident/requests')
def resident_requests():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/requests.html')

@app.route('/resident/file-request')
def resident_file_request():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/file_request.html')

@app.route('/resident/complaints')
def resident_complaints():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/complaints.html')

@app.route('/resident/file-complaint')
def resident_file_complaint():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/file_complaint.html')

@app.route('/resident/household')
def resident_household():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/household.html')

# ── Auth API ──────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    user = query("SELECT * FROM users WHERE username = ?", [username], one=True)
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['resident_id'] = user['resident_id']
        return jsonify({'success': True, 'role': user['role'], 'username': user['username']})
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
            'resident_id': session.get('resident_id')
        })
    return jsonify({'logged_in': False})

# ── Dashboard Stats API ───────────────────────────────────────────

@app.route('/api/dashboard-stats')
@admin_required
def api_dashboard_stats():
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

    # Recent activity
    recent = query("""
        SELECT 'request' as type, d.id, r.full_name, d.document_type, d.status, d.date_requested as date
        FROM document_requests d JOIN residents r ON d.resident_id = r.id
        ORDER BY d.date_requested DESC LIMIT 5
    """)
    recent_activity = [dict_row(r) for r in recent]

    return jsonify({
        'total_residents': total_residents,
        'total_households': total_households,
        'pending_requests': pending_requests,
        'open_complaints': open_complaints,
        'monthly_requests': monthly_data,
        'status_distribution': status_data,
        'blotter_status': blotter_data,
        'recent_activity': recent_activity
    })

# ── Residents API ─────────────────────────────────────────────────

@app.route('/api/residents', methods=['GET', 'POST'])
@admin_required
def api_residents():
    if request.method == 'GET':
        search = request.args.get('search', '')
        household_id = request.args.get('household_id', '')
        params = []
        sql = "SELECT r.*, h.household_code, h.address as household_address FROM residents r LEFT JOIN households h ON r.household_id = h.id WHERE 1=1"
        if search:
            sql += " AND r.full_name LIKE ?"
            params.append(f'%{search}%')
        if household_id:
            sql += " AND r.household_id = ?"
            params.append(household_id)
        sql += " ORDER BY r.full_name"
        rows = query(sql, params)
        result = [dict_row(r) for r in rows]
        for r in result:
            r['age'] = compute_age(r['birthdate'])
        return jsonify(result)

    data = request.get_json()
    rid = query(
        "INSERT INTO residents (full_name, birthdate, sex, civil_status, contact_number, email, household_id, voter_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [data['full_name'], data['birthdate'], data['sex'], data['civil_status'],
         data.get('contact_number', ''), data.get('email', ''), data.get('household_id'), int(data.get('voter_status', 0))]
    )
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if username and password:
        existing = query("SELECT id FROM users WHERE username = ?", [username], one=True)
        if not existing:
            query(
                "INSERT INTO users (username, password_hash, role, resident_id) VALUES (?, ?, 'resident', ?)",
                [username, generate_password_hash(password), rid]
            )
    return jsonify({'success': True, 'id': rid}), 201

@app.route('/api/residents/<int:rid>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
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
        return jsonify({'success': True})

    query("DELETE FROM residents WHERE id = ?", [rid])
    return jsonify({'success': True})

# ── Households API ────────────────────────────────────────────────

@app.route('/api/households', methods=['GET', 'POST'])
@admin_required
def api_households():
    if request.method == 'GET':
        search = request.args.get('search', '')
        sql = """
            SELECT h.*, r.full_name as head_name,
                (SELECT COUNT(*) FROM residents WHERE household_id = h.id) as member_count
            FROM households h
            LEFT JOIN residents r ON h.head_resident_id = r.id
        """
        params = []
        if search:
            sql += " WHERE h.household_code LIKE ? OR h.address LIKE ?"
            params.extend([f'%{search}%', f'%{search}%'])
        sql += " ORDER BY h.household_code"
        rows = query(sql, params)
        return jsonify([dict_row(r) for r in rows])

    data = request.get_json()
    hid = query(
        "INSERT INTO households (household_code, head_resident_id, address) VALUES (?, ?, ?)",
        [data['household_code'], data.get('head_resident_id'), data['address']]
    )
    if data.get('head_resident_id'):
        query("UPDATE residents SET household_id = ? WHERE id = ?", [hid, data['head_resident_id']])
    return jsonify({'success': True, 'id': hid}), 201

@app.route('/api/households/<int:hid>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
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
        return jsonify({'success': True})

    query("DELETE FROM households WHERE id = ?", [hid])
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
def api_my_household_add_member():
    resident_id = session.get('resident_id')
    if not resident_id:
        return jsonify({'error': 'No resident profile linked'}), 400
    resident = query("SELECT * FROM residents WHERE id = ?", [resident_id], one=True)
    if not resident or not resident['household_id']:
        return jsonify({'error': 'You must belong to a household first'}), 400
    data = request.get_json()
    new_id = query(
        "INSERT INTO residents (full_name, birthdate, sex, civil_status, contact_number, email, household_id, voter_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [data['full_name'], data['birthdate'], data['sex'], data['civil_status'],
         data.get('contact_number', ''), data.get('email', ''), resident['household_id'], int(data.get('voter_status', 0))]
    )
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if username and password:
        existing = query("SELECT id FROM users WHERE username = ?", [username], one=True)
        if not existing:
            query(
                "INSERT INTO users (username, password_hash, role, resident_id) VALUES (?, ?, 'resident', ?)",
                [username, generate_password_hash(password), new_id]
            )
    return jsonify({'success': True, 'id': new_id}), 201

# ── Document Requests API ─────────────────────────────────────────

@app.route('/api/requests', methods=['GET', 'POST'])
@login_required
def api_requests():
    if request.method == 'GET':
        resident_id = request.args.get('resident_id', '')
        sql = """
            SELECT d.*, r.full_name as resident_name, h.address
            FROM document_requests d
            JOIN residents r ON d.resident_id = r.id
            LEFT JOIN households h ON r.household_id = h.id
            WHERE 1=1
        """
        params = []
        if resident_id:
            sql += " AND d.resident_id = ?"
            params.append(resident_id)
        # Admin sees all; residents see only their own
        if session.get('role') in ('admin', 'staff') and not resident_id:
            pass
        else:
            sql += " AND d.resident_id = ?"
            params.append(session.get('resident_id'))
        sql += " ORDER BY d.date_requested DESC"
        rows = query(sql, params)
        return jsonify([dict_row(r) for r in rows])

    data = request.get_json()
    resident_id = session.get('resident_id') if session.get('role') == 'resident' else data.get('resident_id')
    if not resident_id:
        return jsonify({'error': 'Resident ID required'}), 400
    rid = query(
        "INSERT INTO document_requests (resident_id, document_type, purpose, status) VALUES (?, ?, ?, 'Pending')",
        [resident_id, data['document_type'], data.get('purpose', '')]
    )
    return jsonify({'success': True, 'id': rid}), 201

@app.route('/api/requests/<int:rid>', methods=['PUT'])
@login_required
def api_update_request(rid):
    data = request.get_json()
    if 'status' in data:
        released = datetime.now().isoformat() if data['status'] == 'Released' else None
        query(
            "UPDATE document_requests SET status=?, notes=?, date_released=? WHERE id=?",
            [data['status'], data.get('notes', ''), released, rid]
        )
    return jsonify({'success': True})

# ── Blotter API ───────────────────────────────────────────────────

@app.route('/api/blotter', methods=['GET', 'POST'])
@login_required
def api_blotter():
    if request.method == 'GET':
        sql = """
            SELECT b.*, r.full_name as complainant_name, r.contact_number as complainant_contact
            FROM blotter b
            JOIN residents r ON b.complainant_id = r.id
            WHERE 1=1
        """
        params = []
        if session.get('role') == 'resident':
            sql += " AND b.complainant_id = ?"
            params.append(session.get('resident_id'))
        sql += " ORDER BY b.date_filed DESC"
        rows = query(sql, params)
        return jsonify([dict_row(r) for r in rows])

    data = request.get_json()
    complainant_id = session.get('resident_id') if session.get('role') == 'resident' else data.get('complainant_id')
    bid = query(
        "INSERT INTO blotter (complainant_id, respondent_name, incident_details, incident_date, incident_location) "
        "VALUES (?, ?, ?, ?, ?)",
        [complainant_id, data['respondent_name'], data['incident_details'],
         data.get('incident_date'), data.get('incident_location')]
    )
    return jsonify({'success': True, 'id': bid}), 201

@app.route('/api/blotter/<int:bid>', methods=['PUT'])
@admin_required
def api_update_blotter(bid):
    data = request.get_json()
    resolved = None
    if data.get('status') in ('Resolved', 'Dismissed'):
        resolved = datetime.now().isoformat()
    query(
        "UPDATE blotter SET status=?, resolution_notes=?, date_resolved=? WHERE id=?",
        [data.get('status', 'Filed'), data.get('resolution_notes', ''), resolved, bid]
    )
    return jsonify({'success': True})

# ── Announcements API ─────────────────────────────────────────────

@app.route('/api/announcements', methods=['GET', 'POST'])
@login_required
def api_announcements():
    if request.method == 'GET':
        rows = query("SELECT * FROM announcements ORDER BY created_at DESC")
        return jsonify([dict_row(r) for r in rows])

    if session.get('role') not in ('admin', 'staff'):
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json()
    aid = query(
        "INSERT INTO announcements (title, description, category, event_date, created_by) VALUES (?, ?, ?, ?, ?)",
        [data['title'], data['description'], data['category'], data.get('event_date'), session['user_id']]
    )
    return jsonify({'success': True, 'id': aid}), 201

@app.route('/api/announcements/<int:aid>', methods=['PUT', 'DELETE'])
@admin_required
def api_announcement(aid):
    if request.method == 'PUT':
        data = request.get_json()
        query(
            "UPDATE announcements SET title=?, description=?, category=?, event_date=? WHERE id=?",
            [data['title'], data['description'], data['category'], data.get('event_date'), aid]
        )
        return jsonify({'success': True})

    query("DELETE FROM announcements WHERE id = ?", [aid])
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
    # Ensure DB exists
    if not os.path.exists(DATABASE):
        from database.seed import seed
        seed()
    app.run(debug=True, host='0.0.0.0', port=5000)

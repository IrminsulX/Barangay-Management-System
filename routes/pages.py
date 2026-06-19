from flask import redirect, render_template, session, url_for
from config import app, ADMIN_ROLES

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

@app.route('/resident/dashboard')
def resident_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/dashboard.html', active_page='dashboard')

@app.route('/resident/home')
def resident_home():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/home.html', active_page='home')

@app.route('/resident/announcements/<int:aid>')
def resident_announcement_detail(aid):
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('resident/announcement_detail.html', active_page='home')

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

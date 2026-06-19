"""
Barangay Management System — Flask Application
Complete REST API backend with SQLite database.
"""
import os
import sqlite3
from config import app, DATABASE
from helpers import close_db, query

# ── Teardown ────────────────────────────────────────────────────────

app.teardown_appcontext(close_db)

# ── Template Filters ─────────────────────────────────────────────

@app.template_filter('fmt_date')
def fmt_date(dt_str):
    if not dt_str:
        return ''
    parts = str(dt_str).split(' ')[0].split('-')
    if len(parts) == 3:
        return f"{parts[1]}/{parts[2]}/{parts[0]}"
    return str(dt_str)

# ── Route Imports ────────────────────────────────────────────────

import routes.pages
import routes.api

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

    # Migration: add new columns to announcements table
    if os.path.exists(DATABASE):
        try:
            conn = sqlite3.connect(DATABASE)
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.execute("PRAGMA table_info(announcements)")
            cols = [row[1] for row in cur.fetchall()]
            if 'is_active' not in cols:
                conn.execute("ALTER TABLE announcements ADD COLUMN is_active INTEGER DEFAULT 1")
            if 'is_pinned' not in cols:
                conn.execute("ALTER TABLE announcements ADD COLUMN is_pinned INTEGER DEFAULT 0")
            if 'image_path' not in cols:
                conn.execute("ALTER TABLE announcements ADD COLUMN image_path TEXT")
            if 'published_at' not in cols:
                conn.execute("ALTER TABLE announcements ADD COLUMN published_at TIMESTAMP")
            if 'updated_at' not in cols:
                conn.execute("ALTER TABLE announcements ADD COLUMN updated_at TIMESTAMP")
            conn.commit()
        finally:
            try: conn.close()
            except: pass

    debug_mode = os.environ.get('FLASK_DEBUG', '1') == '1'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)

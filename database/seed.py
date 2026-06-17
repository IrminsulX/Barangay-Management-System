"""
Seed script — populates the database with sample data.
Run with: python database/seed.py
"""
import sqlite3
import os
from datetime import datetime, timedelta
import random
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'barangay.db')

def seed():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Enable foreign keys
    cur.execute("PRAGMA foreign_keys = ON")

    # Create tables from schema
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r') as f:
        cur.executescript(f.read())

    # ── Households ──
    households = [
        ('BRGY-001', 'Santos Family', '123 Mabini St, Barangay 779'),
        ('BRGY-002', 'Reyes Family', '456 Rizal Ave, Barangay 779'),
        ('BRGY-003', 'Cruz Family', '789 Bonifacio St, Barangay 779'),
        ('BRGY-004', 'Garcia Family', '321 Luna St, Barangay 779'),
        ('BRGY-005', 'Mendoza Family', '654 Aguinaldo St, Barangay 779'),
    ]
    for code, head, addr in households:
        cur.execute(
            "INSERT INTO households (household_code, address) VALUES (?, ?)",
            (code, addr)
        )

    # ── Residents ──
    residents_data = [
        ('Juan Santos', '1985-03-15', 'Male', 'Married', '09171234567', 1, 1),
        ('Maria Santos', '1988-07-22', 'Female', 'Married', '09171234568', 1, 1),
        ('Pedro Santos', '2010-01-10', 'Male', 'Single', '09171234569', 1, 0),
        ('Ana Reyes', '1992-11-05', 'Female', 'Single', '09172345678', 2, 1),
        ('Carlos Reyes', '1965-09-18', 'Male', 'Married', '09172345679', 2, 1),
        ('Elena Reyes', '1968-04-30', 'Female', 'Married', '09172345670', 2, 1),
        ('Miguel Cruz', '1990-02-14', 'Male', 'Married', '09173456789', 3, 1),
        ('Isabel Cruz', '1993-08-08', 'Female', 'Married', '09173456780', 3, 1),
        ('Tomas Cruz', '2015-06-20', 'Male', 'Single', '09173456781', 3, 0),
        ('Luisa Garcia', '1982-12-25', 'Female', 'Widowed', '09174567890', 4, 1),
        ('Jose Garcia Jr.', '2005-05-08', 'Male', 'Single', '09174567891', 4, 0),
        ('Maria Garcia', '2008-09-17', 'Female', 'Single', '09174567892', 4, 0),
        ('Ramon Mendoza', '1975-07-03', 'Male', 'Married', '09175678901', 5, 1),
        ('Luz Mendoza', '1978-01-29', 'Female', 'Married', '09175678902', 5, 1),
        ('Mark Mendoza', '2000-11-11', 'Male', 'Single', '09175678903', 5, 1),
    ]

    for r in residents_data:
        cur.execute(
            "INSERT INTO residents (full_name, birthdate, sex, civil_status, contact_number, email, household_id, voter_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (r[0], r[1], r[2], r[3], r[4], '', r[5], r[6])
        )

    # Set household heads
    cur.execute("UPDATE households SET head_resident_id = 1 WHERE id = 1")
    cur.execute("UPDATE households SET head_resident_id = 4 WHERE id = 2")
    cur.execute("UPDATE households SET head_resident_id = 7 WHERE id = 3")
    cur.execute("UPDATE households SET head_resident_id = 10 WHERE id = 4")
    cur.execute("UPDATE households SET head_resident_id = 13 WHERE id = 5")

    # ── Users ──
    users_data = [
        ('admin', generate_password_hash('admin123'), 'admin', None),
        ('staff1', generate_password_hash('staff123'), 'staff', None),
        ('juan.santos', generate_password_hash('resident123'), 'resident', 1),
        ('ana.reyes', generate_password_hash('resident123'), 'resident', 4),
        ('miguel.cruz', generate_password_hash('resident123'), 'resident', 7),
        ('luisa.garcia', generate_password_hash('resident123'), 'resident', 10),
        ('ramon.mendoza', generate_password_hash('resident123'), 'resident', 13),
    ]
    for u in users_data:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, resident_id) VALUES (?, ?, ?, ?)",
            u
        )

    # ── Document Requests ──
    doc_types = ['Barangay Clearance', 'Certificate of Residency', 'Certificate of Indigency',
                 'Business Permit Endorsement', 'Certificate of Good Moral', 'Barangay ID']
    statuses = ['Pending', 'Processing', 'Ready', 'Released']
    purposes = ['Employment requirement', 'School enrollment', 'Business permit application',
                'Government ID application', 'Financial assistance', 'Court requirement']

    requests_data = []
    base_date = datetime.now() - timedelta(days=30)
    for i, resident_id in enumerate([1, 4, 7, 10, 13, 1, 4, 7], start=1):
        req_date = base_date + timedelta(days=i*3)
        rel_date = req_date + timedelta(days=random.randint(1, 7)) if random.random() > 0.4 else None
        status = random.choice(statuses) if i > 2 else 'Pending'
        requests_data.append((
            resident_id,
            random.choice(doc_types),
            random.choice(purposes),
            status,
            req_date.isoformat(),
            rel_date.isoformat() if rel_date and status == 'Released' else None,
            None
        ))

    for r in requests_data:
        cur.execute(
            "INSERT INTO document_requests (resident_id, document_type, purpose, status, date_requested, date_released, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            r
        )

    # ── Blotter ──
    blotter_data = [
        (1, 'Peter Lim', 'Noise complaint — loud party past midnight at 123 Mabini St.',
         '2026-06-01 23:30:00', '123 Mabini St', 'Resolved',
         'Parties involved were warned and reconciled. Noise ordinance reminder issued.', '2026-06-05 10:00:00'),
        (4, 'Unknown person', 'Report of lost wallet near the barangay hall.',
         '2026-06-10 14:00:00', 'Barangay Hall vicinity', 'Under Investigation',
         'CCTV footage being reviewed.', None),
        (7, 'Nestor Cruz', 'Boundary dispute between neighbors over fence line.',
         '2026-06-12 09:00:00', '789 Bonifacio St', 'Filed',
         None, None),
        (10, 'Jun Garcia', 'Verbal altercation at the public market.',
         '2026-06-14 16:30:00', 'Barangay Public Market', 'Filed',
         None, None),
        (13, 'Ricky Mendoza', 'Petty theft — bicycle stolen from front yard.',
         '2026-06-08 20:00:00', '654 Aguinaldo St', 'Resolved',
         'Suspect identified and barangay settlement reached. Bicycle returned.', '2026-06-11 15:00:00'),
    ]
    for b in blotter_data:
        cur.execute(
            "INSERT INTO blotter (complainant_id, respondent_name, incident_details, incident_date, "
            "incident_location, status, resolution_notes, date_resolved) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            b
        )

    # ── Announcements ──
    announcements_data = [
        ('Barangay Clean-Up Drive', 'Join us for the monthly clean-up drive this Saturday. '
         'Meet at the barangay hall at 6:00 AM. Bring your own brooms and gloves.',
         'Event', '2026-06-22', 1),
        ('Reminder: Garbage Collection Schedule', 'Please follow the garbage collection schedule: '
         'Mondays, Wednesdays, and Fridays for biodegradable waste; Tuesdays and Thursdays for non-biodegradable.',
         'General', None, 1),
        ('Free Health Check-Up', 'The Barangay Health Center, in partnership with the City Health Office, '
         'will conduct a free health check-up for all residents. Services include blood pressure screening, '
         'blood sugar testing, and dental check-up.',
         'Health', '2026-06-25', 1),
        ('New Ordinance: Curfew for Minors', 'Barangay Ordinance No. 2026-03: Curfew for minors under 18 '
         'from 10:00 PM to 5:00 AM. Parents/guardians will be held accountable for violations.',
         'Ordinance', '2026-07-01', 1),
        ('Peace and Order Advisory', 'Report any suspicious activities to the barangay tanod hotline: '
         '0917-123-4567. Let us work together to maintain peace and order in our community.',
         'Peace & Order', None, 1),
    ]
    base_ann_date = datetime.now() - timedelta(days=15)
    for i, a in enumerate(announcements_data, start=1):
        created = (base_ann_date + timedelta(days=i*2)).isoformat()
        cur.execute(
            "INSERT INTO announcements (title, description, category, event_date, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (a[0], a[1], a[2], a[3], a[4], created)
        )

    conn.commit()
    conn.close()
    print("Database seeded successfully!")
    print("Login credentials:")
    print("  Admin:     admin / admin123")
    print("  Staff:     staff1 / staff123")
    print("  Resident:  juan.santos / resident123")
    print("  Resident:  ana.reyes / resident123")

if __name__ == '__main__':
    seed()

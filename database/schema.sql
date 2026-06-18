-- Barangay Management System - Database Schema
-- Run this file to create all tables

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'staff', 'resident')),
    resident_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (resident_id) REFERENCES residents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS households (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    household_code TEXT UNIQUE NOT NULL,
    head_resident_id INTEGER,
    address TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (head_resident_id) REFERENCES residents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS residents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    birthdate DATE NOT NULL,
    sex TEXT NOT NULL CHECK(sex IN ('Male', 'Female')),
    civil_status TEXT NOT NULL CHECK(civil_status IN ('Single', 'Married', 'Widowed', 'Divorced', 'Separated')),
    contact_number TEXT,
    email TEXT,
    household_id INTEGER,
    voter_status INTEGER DEFAULT 0 CHECK(voter_status IN (0, 1)),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (household_id) REFERENCES households(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS document_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resident_id INTEGER NOT NULL,
    document_type TEXT NOT NULL CHECK(document_type IN (
        'Barangay Clearance', 'Certificate of Residency',
        'Certificate of Indigency', 'Business Permit Endorsement',
        'Certificate of Good Moral', 'Barangay ID'
    )),
    purpose TEXT,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Processing', 'Ready', 'Released', 'Rejected')),
    date_requested TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_released TIMESTAMP,
    notes TEXT,
    FOREIGN KEY (resident_id) REFERENCES residents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS blotter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    complainant_id INTEGER NOT NULL,
    respondent_name TEXT NOT NULL,
    incident_details TEXT NOT NULL,
    incident_date TIMESTAMP,
    incident_location TEXT,
    status TEXT NOT NULL DEFAULT 'Filed' CHECK(status IN ('Filed', 'Under Investigation', 'Resolved', 'Dismissed')),
    resolution_notes TEXT,
    date_filed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_resolved TIMESTAMP,
    FOREIGN KEY (complainant_id) REFERENCES residents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('General', 'Event', 'Ordinance', 'Health', 'Peace & Order', 'Disaster')),
    event_date DATE,
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id INTEGER,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

import sqlite3
import os
from flask import g, current_app


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DB_PATH'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
        g.db.execute('PRAGMA journal_mode = WAL')
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def get_db_direct(db_path):
    """Get a DB connection outside of request context (e.g. background threads)."""
    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA journal_mode = WAL')
    return conn


def init_db(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        _create_schema(db)
        _seed_defaults(db)


def _create_schema(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            full_name TEXT,
            is_active INTEGER DEFAULT 1,
            is_root INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT,
            last_ip TEXT
        );

        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            category TEXT
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_permissions (
            user_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            granted INTEGER DEFAULT 1,
            PRIMARY KEY (user_id, permission_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            category TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS alert_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            rule_description TEXT,
            rule_level INTEGER,
            rule_groups TEXT,
            mitre_ids TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            total_count INTEGER DEFAULT 1,
            status TEXT DEFAULT 'open',
            assigned_to INTEGER,
            notes TEXT,
            closed_at TEXT,
            closed_by INTEGER,
            FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (closed_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            agent_id TEXT,
            agent_name TEXT,
            agent_ip TEXT,
            agent_labels TEXT,
            raw_json TEXT,
            FOREIGN KEY (case_id) REFERENCES alert_cases(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS rule_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_source TEXT NOT NULL,
            target_file TEXT NOT NULL,
            field_name TEXT,
            field_value TEXT,
            match_type TEXT,
            is_negate INTEGER DEFAULT 1,
            full_xml TEXT,
            case_id INTEGER,
            created_by INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            status TEXT DEFAULT 'active',
            notes TEXT,
            diff_before TEXT,
            diff_after TEXT,
            FOREIGN KEY (case_id) REFERENCES alert_cases(id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS backup_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            files_backed_up TEXT,
            backup_path TEXT,
            started_at TEXT DEFAULT (datetime('now')),
            completed_at TEXT,
            status TEXT DEFAULT 'in_progress',
            size_bytes INTEGER,
            error_message TEXT
        );

        CREATE TABLE IF NOT EXISTS notification_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            subject TEXT,
            message TEXT,
            recipients TEXT,
            sent INTEGER DEFAULT 0,
            sent_at TEXT,
            error TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS wazuh_restarts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            triggered_by INTEGER,
            reason TEXT,
            status TEXT DEFAULT 'pending',
            output TEXT,
            started_at TEXT DEFAULT (datetime('now')),
            completed_at TEXT,
            FOREIGN KEY (triggered_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS webhook_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            rule_id TEXT,
            rule_description TEXT,
            resolution TEXT,
            payload TEXT,
            response_status INTEGER,
            response_body TEXT,
            success INTEGER DEFAULT 0,
            attempt INTEGER DEFAULT 1,
            error TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_alert_cases_rule_id ON alert_cases(rule_id);
        CREATE INDEX IF NOT EXISTS idx_alert_cases_status ON alert_cases(status);
        CREATE INDEX IF NOT EXISTS idx_alert_events_case_id ON alert_events(case_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_webhook_log_created ON webhook_log(created_at);
    ''')
    db.commit()

    # Migration: add wazuh_alert_id for deduplication (safe on existing DBs)
    try:
        db.execute('ALTER TABLE alert_events ADD COLUMN wazuh_alert_id TEXT')
        db.execute(
            '''CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_events_wazuh_id
               ON alert_events(wazuh_alert_id)
               WHERE wazuh_alert_id IS NOT NULL'''
        )
        db.commit()
    except Exception:
        pass  # Column already exists


PERMISSIONS = [
    ('view_dashboard',          'View the dashboard',                         'Dashboard'),
    ('view_alerts',             'View alert cases list',                      'Alerts'),
    ('view_alert_details',      'View individual alert case details',         'Alerts'),
    ('close_alerts',            'Close, ignore, or act on alert cases',       'Alerts'),
    ('view_rules',              'View all Wazuh rules',                       'Rules'),
    ('create_custom_rules',     'Create new custom rules',                    'Rules'),
    ('edit_custom_rules',       'Edit existing custom rules',                 'Rules'),
    ('edit_raw_xml',            'Edit the raw XML of rules directly',         'Rules'),
    ('delete_custom_rules',     'Delete custom rules',                        'Rules'),
    ('view_exceptions',         'View rule exceptions',                       'Exceptions'),
    ('create_custom_exceptions','Create exceptions for custom rules',         'Exceptions'),
    ('create_default_exceptions','Create exceptions for default Wazuh rules', 'Exceptions'),
    ('delete_exceptions',       'Delete rule exceptions',                     'Exceptions'),
    ('view_suppressions',       'View rule suppressions',                     'Suppressions'),
    ('create_custom_suppressions','Create suppressions for custom rules',     'Suppressions'),
    ('create_default_suppressions','Create suppressions for default rules',   'Suppressions'),
    ('delete_suppressions',     'Delete rule suppressions',                   'Suppressions'),
    ('view_health',             'View Wazuh service health status',           'Health'),
    ('restart_wazuh',           'Restart the Wazuh manager service',          'Health'),
    ('view_settings',           'View platform settings',                     'Settings'),
    ('manage_settings',         'Modify platform settings',                   'Settings'),
    ('manage_users',            'Create, edit, deactivate users',             'Settings'),
    ('manage_roles',            'Create and manage roles and permissions',     'Settings'),
    ('view_audit_log',          'View the audit/activity log',                'Settings'),
    ('manage_backups',          'Configure and trigger backups',              'Settings'),
    ('manage_integrations',     'Configure webhook integrations and automation', 'Settings'),
    ('bulk_actions',            'Perform bulk ignore and suppress on alert cases', 'Alerts'),
]


def _seed_defaults(db):
    from werkzeug.security import generate_password_hash

    # Seed permissions
    for name, desc, cat in PERMISSIONS:
        db.execute(
            'INSERT OR IGNORE INTO permissions (name, description, category) VALUES (?, ?, ?)',
            (name, desc, cat)
        )

    # Create root user if none exists
    existing = db.execute('SELECT id FROM users WHERE is_root = 1').fetchone()
    if not existing:
        pw_hash = generate_password_hash('admin')
        db.execute(
            '''INSERT OR IGNORE INTO users (username, password_hash, full_name, is_root, is_active)
               VALUES (?, ?, ?, 1, 1)''',
            ('admin', pw_hash, 'Administrator')
        )

    # Create default roles
    roles = [
        ('Analyst',   'Can view alerts and create exceptions/suppressions'),
        ('Engineer',  'Full rule and exception management'),
        ('Auditor',   'Read-only access to all data'),
        ('Operator',  'Can view health and restart wazuh'),
    ]
    for rname, rdesc in roles:
        db.execute('INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)', (rname, rdesc))

    db.commit()

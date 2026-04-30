# Wazuh Morpheus

A web-based management platform for Wazuh SIEM. Wazuh Morpheus provides case management for alert triage, a rule exception and suppression builder, real-time health monitoring, indexer health tracking, configurable email and webhook notifications, user and role management with granular permissions, scheduled backups, and a full audit trail of every action taken on the platform.

Built with Flask, SQLite3, lxml, and vanilla JavaScript. Designed to run directly on a Wazuh manager server.

---

## Table of Contents

- [Features](#features)
- [Alert Case Management](#alert-case-management)
- [Rules Management](#rules-management)
- [Exception Builder](#exception-builder)
- [Suppression Management](#suppression-management)
- [Health Monitoring](#health-monitoring)
- [Indexer Monitoring](#indexer-monitoring)
- [Notifications](#notifications)
- [Webhook Integration](#webhook-integration)
- [User Management and Permissions](#user-management-and-permissions)
- [Audit Logging](#audit-logging)
- [Backups](#backups)
- [Settings](#settings)
- [Configuration](#configuration)
- [Installation](#installation)
- [Technology Stack](#technology-stack)
- [Security Notes](#security-notes)

---

## Features

- Real-time alert ingestion from Wazuh's alerts.json with automatic case grouping by rule ID
- Full case lifecycle: open, investigate, create exception, suppress, ignore, reopen
- Bulk actions for ignoring or suppressing multiple cases at once
- Interactive exception builder with common field detection, pattern suggestions, and searchable field dropdown
- Custom rule creation with live XML preview
- Browsing and searching both custom and default Wazuh rules
- Real-time health dashboard: Wazuh service status, CPU, memory, disk, and network
- Indexer cluster health monitoring (OpenSearch / Elasticsearch)
- Indexer log activity monitoring with stale data detection
- Per-mount disk threshold alerts
- Archives log gap detection (no-log alerting)
- Configurable email notifications (SMTP or Postfix relay) with customizable HTML templates
- Webhook integration for forwarding events to SOAR platforms, Logic Apps, or any HTTP endpoint
- Role-based access control with 23+ granular permissions
- Per-user permission overrides independent of roles
- Full audit log of every action with export to CSV
- Scheduled backups of rule files with compression and retention
- Configurable event columns on the alert detail page
- Field silence list to hide noisy fields from the UI
- Wazuh field index updatable from Elasticsearch/OpenSearch mapping output
- Quiet hours to suppress non-critical alerts during maintenance windows
- Dark and light theme support

---

## Alert Case Management

The platform ingests alerts from Wazuh's `alerts.json` file in real time using a background tailer thread. Alerts are grouped into cases by rule ID. Each case tracks the first and last seen timestamps, total event count, and unique agent count.

### Cases List

- Paginated list of all alert cases (50 per page)
- Filter by status: open, ignored, excepted, suppressed, or all
- Filter by minimum rule level
- Search by rule ID or description
- Sort by level, rule ID, description, event count, first seen, or last seen
- Status summary showing counts per status
- Assign cases to users
- Bulk ignore or bulk suppress selected cases
- Live polling for new cases without page refresh

### Case Detail

- Full case metadata: rule ID, description, level, first/last seen, event count
- Event accordion showing individual alert events with configurable column headers
- Flat field extraction from all events with values displayed per row
- Common field detection: fields with identical values across all events are highlighted, making it easy to identify reliable exception candidates
- Similar field detection: fields with differing values that share common substrings, suggesting pattern-based negation
- Rule XML viewer showing the current rule logic
- Inline raw XML editing for rules in the exceptions file
- History of all exceptions and suppressions applied to the rule
- Buttons to create an exception, suppress the rule, or ignore the case
- Load all events (paginated fetch beyond the initial 100)
- Configurable event columns: choose which fields appear in event headers via Settings

### Alert Import

A manual import endpoint reads the configured alerts.json file and processes all events, useful for backfilling historical data or re-importing after a database reset.

---

## Rules Management

### Browsing Rules

- Dual-source rule browser: custom rules from your custom rules file and default Wazuh rules from the ruleset directory
- Filter by source (custom, default, or all)
- Search by rule ID or description
- Sort by ID, level, source, or description
- Paginated (100 per page)
- Badges indicating which rules have active suppressions or exceptions
- View full rule XML and parsed structure

### Custom Rule Creation

- Interactive rule builder form with live XML preview
- Fields: rule ID (must be >= 100000), level, description
- Conditional fields: if_sid, if_group, match, regex with type selectors
- Field builder: add field-level conditions with a searchable field name dropdown (populated from your Wazuh index mapping), match type selector (pcre2, osmatch, osregex), and negate toggle
- Frequency and timeframe settings
- MITRE ATT&CK ID assignment
- Custom options and groups
- On submission, the rule is written to the custom rules file and a notification is sent

---

## Exception Builder

The exception builder is accessible from the alert case detail page. It adds negated field conditions to a rule so that specific alert patterns are excluded from future firing.

- For custom rules (ID >= 100000): the negated field is added directly to the rule in the custom rules file
- For default rules (ID < 100000): the rule is copied to the default rules exceptions file with `overwrite="yes"` and the negated field is added there
- Supports multiple match types: pcre2, osmatch, osregex
- Searchable field dropdown populated from all fields extracted from the case events
- Common fields are shown as clickable chips for one-click addition
- Similar field pattern suggestions are shown as clickable chips
- Multiple fields can be negated in a single exception
- Each exception is recorded in the database with a before/after XML diff

---

## Suppression Management

Suppression sets a rule's level to 0 and adds `noalert="1"`, silencing all alerts from that rule.

- For custom rules: the level is set to 0 directly in the custom rules file
- For default rules: the rule is copied to the suppressions file with `overwrite="yes"` and level set to 0
- Suppressions list page shows all suppressed rules
- Unsuppress to restore the rule to its original level
- Duplicate suppression attempts are rejected with a clear error

---

## Health Monitoring

The health dashboard provides real-time visibility into the Wazuh server and its dependencies.

### Wazuh Service Status

- Checks `systemctl is-active wazuh-manager.service`
- Displays running, stopped, or failed status
- Restart button triggers a background restart with live status polling
- Restart history log with systemctl output and journalctl logs

### System Metrics

- **Disk**: All mount points with usage percentage. Configurable per-mount thresholds with email alerts when exceeded.
- **Memory**: Total, used, free, swap, and percentage (parsed from `free -m`).
- **CPU**: Current usage percentage and 1/5/15-minute load averages. A 5-hour history chart is maintained with one sample per poll interval.
- **Network**: Per-interface RX/TX bytes, packets, and errors (from `/proc/net/dev`).

### Poll Interval

The health dashboard refresh interval is configurable (default 30 seconds, minimum 5 seconds). All metrics are fetched via a single API call and rendered client-side.

---

## Indexer Monitoring

Monitor your OpenSearch or Elasticsearch indexers for cluster health problems and stale data. Each indexer can have one or both monitor types configured.

### Cluster Health Monitor

- Queries `GET /_cluster/health` on the configured indexer URL
- Reports cluster status (green, yellow, red), node count, and unassigned shards
- Configurable alert threshold: alert on red only, yellow and red, or any non-green status
- Sends an `indexer_issue` notification when the threshold is crossed

### Log Activity Monitor

- Queries the latest document by `@timestamp` in the configured index pattern (e.g., `wazuh-alerts-*`)
- Reports the age of the most recent document
- Alerts if no new data has arrived within the configured threshold (e.g., 10 minutes)
- Detects stale data where the latest timestamp has not changed between checks

### Configuration

Each monitor has its own check interval (minimum 30 seconds), credentials, SSL verification toggle, and enable/disable switch. A test connection button is available before saving to verify connectivity and credentials.

---

## Notifications

### Email Delivery

Two backends are supported. SMTP for standard email servers (with TLS/STARTTLS support) and Postfix for local mail relay without authentication. Both can be tested from the settings page with a test recipient.

### Notification Events

The platform sends notifications for 11 event types:

| Event | Description |
|---|---|
| Exception created | A user created an exception for a rule |
| Suppression created | A rule was suppressed |
| Custom rule created | A new custom rule was added |
| Wazuh restart successful | The Wazuh manager service was restarted successfully |
| Wazuh restart failed | A restart attempt failed |
| Disk threshold exceeded | Disk usage crossed the configured threshold on a mount point |
| Alert case ignored | An alert case was marked as ignored |
| Archives log gap | No new entries appeared in archives.json within the configured threshold |
| Indexer health issue | An indexer is unreachable, unhealthy, or has stale data |
| Bulk ignore | Multiple alert cases were bulk-ignored |
| Bulk suppress | Multiple rules were bulk-suppressed |

Each event type can be individually enabled or disabled. Per-event recipient overrides allow routing specific events to different teams or email addresses.

### Email Templates

Each notification event has a default HTML email template. Custom templates can be created, edited, and previewed from the settings page. Templates use a `{{ variable }}` or `{{ variable:fallback }}` syntax for dynamic values. Each event type has its own set of available template variables (e.g., rule_id, created_by, timestamp, mount, percent).

### Quiet Hours

A configurable quiet window (e.g., 00:00 to 06:00) suppresses non-critical notifications like indexer stale data and archives log gap alerts during scheduled maintenance or low-activity periods.

### Archives Log Gap Detection

A background thread monitors the configured `archives.json` file. If no new entries appear within the configured threshold (default 300 seconds), an `archives_no_log` notification is sent. This detects situations where log forwarding has stopped.

---

## Webhook Integration

Forward case actions to external systems such as Microsoft Logic Apps, SOAR platforms, or any HTTP endpoint that accepts JSON payloads.

### Supported Events

- Case ignored
- Exception created
- Suppression created
- Bulk ignore
- Bulk suppress

Each event can be individually toggled on or off.

### Authentication

- Bearer token (sent as `Authorization: Bearer <token>`)
- Custom header (configurable header name and value)

### Features

- Configurable timeout (1 to 60 seconds) and retry count (0 to 5 attempts)
- Resolution workflow: when integration is enabled, users must select a resolution category (e.g., False Positive, True Positive, Benign Positive, Informational) when closing cases. Resolution options are fully configurable.
- All webhook deliveries are logged with request payload, response status, response body, and any errors
- Test webhook button to verify connectivity before saving
- Delivery log viewable from the integration settings page

### Payload Example

```json
{
  "action": "case_ignored",
  "rule_id": "61138",
  "rule_description": "Windows Defender event",
  "notes": "Benign activity on app server",
  "resolution": "False Positive",
  "username": "analyst1",
  "timestamp": "2026-04-30T15:30:45",
  "case_id": 42
}
```

---

## User Management and Permissions

### Users

- Create, edit, activate, and deactivate user accounts
- Fields: username, password (minimum 6 characters), email, full name
- Root users bypass all permission checks
- Last login time and IP address are tracked

### Roles

- Create named roles with descriptions
- Assign any combination of permissions to a role
- Assign one or more roles to each user
- Delete roles when no longer needed

### Permissions

23+ granular permissions organized by category:

| Category | Permissions |
|---|---|
| Dashboard | View dashboard statistics |
| Alerts | View cases, view case details, close/ignore cases, bulk actions |
| Rules | View rules, create/edit/delete custom rules, edit raw XML |
| Exceptions | View exceptions, create custom exceptions, create default exceptions, delete exceptions |
| Suppressions | View suppressions, create custom suppressions, create default suppressions, delete suppressions |
| Health | View health dashboard, restart Wazuh |
| Settings | View settings, manage settings, manage users, manage roles, view audit log, manage backups, manage integrations |

### Permission Resolution

1. Root users have all permissions automatically
2. Explicit user-level permission overrides (grant or revoke) take priority over roles
3. Role-level permissions apply when no user-level override exists

---

## Audit Logging

Every action on the platform is logged to the audit trail with:

- Timestamp
- Username and user ID
- Action name (e.g., LOGIN, CREATE_EXCEPTION, CLOSE_CASE, UPDATE_WAZUH_PATHS)
- Category (Auth, Alerts, Rules, Health, Settings, UserManagement)
- Details stored as a JSON object with action-specific data
- IP address of the user

The audit log page supports filtering by search text, category, username, and date range. Entries are paginated at 100 per page and can be exported to CSV (up to 10,000 rows).

---

## Backups

Scheduled backups of critical rule files using APScheduler.

### Schedule Types

- **Daily**: run at a specific time each day
- **Weekly**: run on selected days of the week at a specific time
- **Every N hours**: run at a fixed interval
- **Every N days**: run every N days at a specific time

### Features

- Configurable list of files to back up (custom rules, suppressions, exceptions)
- Backup directory path (must be absolute)
- Optional gzip compression
- Retention policy: keep last N backups, older ones are automatically deleted
- Manual trigger button to run a backup immediately
- Backup history log showing status, file sizes, and any errors

---

## Settings

All configuration is managed through the settings page without requiring code changes or application restarts.

### Wazuh File Paths

Configure paths to alerts.json, the default rules directory, custom rules file, suppressions file, default rules exceptions file, and archives.json. Both Linux and Windows paths are supported.

### Field Silence List

Fields in this list are hidden from alert event displays, the exception builder dropdown, and common field detection. Useful for suppressing noisy metadata fields like `rule.firedtimes`, `cluster.node`, `rule.pci_dss`, etc.

### Alert Event Columns

Configure which columns appear in the event accordion header on the alert detail page. Uses a searchable dropdown populated from your Wazuh field index (WazuhFields.json). Fields use dot-notation paths into the parsed alert JSON (e.g., `data.win.system.eventID`, `agent.name`). Special fields `timestamp`, `agent.name`, `agent.ip`, and `agent.id` resolve from database columns.

### Wazuh Field Index

Paste the output of `GET /*/_mapping` from your OpenSearch/Elasticsearch instance to update the list of known alert fields. This populates the searchable field dropdowns used throughout the platform in the exception builder, rule creation form, and event column configuration.

---

## Configuration

All settings are stored in `config.json` at the project root. If the file does not exist on first run, a default configuration is created automatically with standard Wazuh paths.

### Key Sections

| Section | Purpose |
|---|---|
| `app` | Secret key, debug mode, host, port |
| `database` | SQLite database file path |
| `wazuh` | File paths, silenced fields, archives monitoring config |
| `email` | SMTP server configuration |
| `postfix` | Local mail relay configuration |
| `notifications` | Per-event toggles, recipients, quiet hours, disk thresholds |
| `email_templates` | Custom/default toggle per event type |
| `indexers` | Indexer monitor definitions |
| `alerts` | Event column configuration |
| `health` | Dashboard poll interval |
| `integration` | Webhook URL, auth, event toggles, resolution options |
| `backup` | Schedule type, files, compression, retention |

---

## Installation

### Requirements

- Python 3.8+
- A running Wazuh manager server (Linux with systemd)
- pip

### Setup

```bash
cd wazuh_platform
pip install -r requirements.txt
python run.py
```

The application starts on `http://0.0.0.0:5000` by default. On first run, a default `config.json` and SQLite database are created automatically. A default admin user is created with:

- Username: `admin`
- Password: `admin`

Change the password and secret key immediately after first login.

### Production Deployment

For production, use the WSGI entry point:

```bash
python wsgi.py
```

Or with Gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 "wsgi:app"
```

### Running as a systemd Service

Create `/etc/systemd/system/wazuh-morpheus.service`:

```ini
[Unit]
Description=Wazuh Morpheus Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/wazuh_platform
ExecStart=/path/to/wazuh_platform/venv/bin/python wsgi.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```bash
systemctl daemon-reload
systemctl enable wazuh-morpheus
systemctl start wazuh-morpheus
```

### File Paths

Update the Wazuh file paths in Settings to match your server. Default paths assume a standard Wazuh installation:

| Setting | Default Path |
|---|---|
| Alerts JSON | `/var/ossec/logs/alerts/alerts.json` |
| Default Rules | `/var/ossec/ruleset/rules/` |
| Custom Rules | `/var/ossec/etc/rules/customrulesfile.xml` |
| Suppressions | `/var/ossec/etc/rules/suppressions.xml` |
| Exceptions | `/var/ossec/etc/rules/default-rule-exceptions.xml` |
| Archives JSON | `/var/ossec/logs/archives/archives.json` |

---

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Flask (Python) |
| Database | SQLite3 (WAL mode, foreign keys enabled) |
| XML Parsing | lxml with recovery mode |
| Scheduling | APScheduler |
| Email | smtplib (SMTP) / sendmail (Postfix) |
| HTTP Client | requests |
| Frontend | Vanilla JavaScript, Jinja2 templates |
| Styling | Custom CSS per page (no frameworks) |

---

## Security Notes

- Change the default `secret_key` in `config.json` before deploying to production
- Change the default admin password immediately after first login
- The platform needs read/write access to Wazuh rule files -- run as a user with appropriate permissions
- Email passwords and indexer credentials are stored in `config.json` in plaintext -- restrict file permissions accordingly (`chmod 600 config.json`)
- Use a reverse proxy (nginx, Apache) with TLS for production deployments
- The SQLite database contains audit logs and alert data -- include it in your backup strategy

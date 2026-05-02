import json
import os
from flask import (Blueprint, render_template, request, jsonify, session,
                   redirect, url_for, current_app)
from ..auth.decorators import login_required, permission_required
from ..audit.logger import log_action
from ..database import get_db

settings_bp = Blueprint('settings', __name__)

KNOWN_EVENT_TYPES = [
    'exception_created', 'suppression_created', 'rule_created',
    'wazuh_restart_success', 'wazuh_restart_failure',
    'disk_threshold', 'case_ignored', 'archives_no_log',
    'indexer_issue', 'bulk_ignore', 'bulk_suppress',
]

EVENT_LABELS = {
    'exception_created':     'Exception Created',
    'suppression_created':   'Suppression Created',
    'rule_created':          'Custom Rule Created',
    'wazuh_restart_success': 'Wazuh Restart Successful',
    'wazuh_restart_failure': 'Wazuh Restart Failed',
    'disk_threshold':        'Disk Threshold Alert',
    'case_ignored':          'Alert Case Ignored',
    'archives_no_log':       'Archives Log Gap',
    'indexer_issue':          'Indexer Health Issue',
    'bulk_ignore':            'Bulk Ignore',
    'bulk_suppress':          'Bulk Suppress',
}

TEMPLATE_VARS = {
    'exception_created':     ['rule_id', 'field_name', 'field_value', 'created_by', 'notes', 'timestamp'],
    'suppression_created':   ['rule_id', 'created_by', 'notes', 'timestamp'],
    'rule_created':          ['rule_id', 'description', 'created_by', 'timestamp'],
    'wazuh_restart_success': ['triggered_by', 'reason', 'output', 'timestamp'],
    'wazuh_restart_failure': ['triggered_by', 'reason', 'output', 'timestamp'],
    'disk_threshold':        ['mount', 'percent', 'threshold', 'timestamp'],
    'case_ignored':          ['rule_id', 'created_by', 'notes', 'timestamp'],
    'archives_no_log':       ['elapsed', 'path', 'timestamp'],
    'indexer_issue':          ['indexer_name', 'indexer_url', 'monitor_type', 'cluster_status', 'nodes', 'unassigned_shards', 'latest_document', 'document_age', 'index_pattern', 'error', 'timestamp'],
    'bulk_ignore':            ['count', 'case_ids', 'rule_ids', 'created_by', 'notes', 'timestamp'],
    'bulk_suppress':          ['count', 'rule_ids', 'created_by', 'notes', 'timestamp'],
}


def _read_config():
    cfg_path = current_app.config['CONFIG_PATH']
    with open(cfg_path) as f:
        return json.load(f)


def _write_config(cfg):
    cfg_path = current_app.config['CONFIG_PATH']
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f, indent=2)
    # Update live config in-place so any threads holding a reference see the update
    current_app.config['CONFIG'].clear()
    current_app.config['CONFIG'].update(cfg)


@settings_bp.route('/')
@login_required
@permission_required('view_settings')
def general():
    from ..notifications.email_service import EMAILS_DIR
    cfg = _read_config()
    tpl_cfg = cfg.get('email_templates', {})
    email_templates = []
    for et in KNOWN_EVENT_TYPES:
        etc = tpl_cfg.get(et, {})
        custom_path = os.path.join(EMAILS_DIR, 'custom_emails', f'{et}.html')
        email_templates.append({
            'event_type': et,
            'label': EVENT_LABELS.get(et, et),
            'use_custom': etc.get('use_custom', False),
            'has_custom': os.path.exists(custom_path),
        })
    return render_template('settings/general.html', config=cfg,
                           email_templates=email_templates,
                           active_page='settings', active_sub='general')


@settings_bp.route('/wazuh-paths', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_wazuh_paths():
    data = request.get_json() or {}
    cfg = _read_config()

    path_keys = [
        'alerts_json_path', 'default_rules_path',
        'custom_rules_path', 'suppressions_path',
        'default_rules_exceptions_path', 'archives_json_path',
    ]
    for key in path_keys:
        if key in data:
            cfg['wazuh'][key] = data[key]

    if 'no_log_alert_seconds' in data:
        try:
            cfg['wazuh']['no_log_alert_seconds'] = int(data['no_log_alert_seconds'])
        except (TypeError, ValueError):
            cfg['wazuh']['no_log_alert_seconds'] = 300

    _write_config(cfg)
    log_action('UPDATE_WAZUH_PATHS', 'Settings', data)
    return jsonify({'success': True})


@settings_bp.route('/email', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_email():
    data = request.get_json() or {}
    cfg = _read_config()

    email_keys = ['enabled', 'smtp_host', 'smtp_port', 'smtp_user',
                  'smtp_password', 'smtp_tls', 'from_address', 'recipients']
    for key in email_keys:
        if key in data:
            val = data[key]
            if key == 'smtp_port':
                val = max(1, min(65535, int(val))) if val else 587
            if key == 'enabled' or key == 'smtp_tls':
                val = bool(val)
            cfg['email'][key] = val

    _write_config(cfg)
    log_action('UPDATE_EMAIL_SETTINGS', 'Settings', {k: v for k, v in data.items() if k != 'smtp_password'})
    return jsonify({'success': True})


@settings_bp.route('/email/test', methods=['POST'])
@login_required
@permission_required('manage_settings')
def test_email():
    from ..notifications.email_service import send_email_direct
    data = request.get_json() or {}
    cfg = _read_config()
    ec = cfg.get('email', {})

    if not ec.get('enabled') or not ec.get('smtp_host'):
        return jsonify({'error': 'Email is not configured'}), 400

    recipient = (data.get('recipient') or '').strip()
    if not recipient:
        return jsonify({'error': 'Test recipient is required'}), 400

    try:
        send_email_direct(
            smtp_host=ec['smtp_host'],
            smtp_port=int(ec.get('smtp_port', 587)),
            smtp_user=ec.get('smtp_user', ''),
            smtp_password=ec.get('smtp_password', ''),
            smtp_tls=bool(ec.get('smtp_tls', True)),
            from_address=ec.get('from_address', ec.get('smtp_user', '')),
            to_addresses=[recipient],
            subject='Wazuh Morpheus - Email Test',
            body='This is a test email from Wazuh Morpheus. SMTP configuration is working.'
        )
        log_action('TEST_EMAIL', 'Settings', {'recipient': recipient})
        return jsonify({'success': True, 'message': 'Test email sent successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/postfix', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_postfix():
    data = request.get_json() or {}
    cfg = _read_config()

    if 'postfix' not in cfg:
        cfg['postfix'] = {}

    postfix_keys = ['enabled', 'host', 'port', 'from_address', 'username', 'password', 'use_tls']
    for key in postfix_keys:
        if key in data:
            val = data[key]
            if key == 'port':
                val = max(1, min(65535, int(val))) if val else 25
            elif key in ('enabled', 'use_tls'):
                val = bool(val)
            cfg['postfix'][key] = val

    _write_config(cfg)
    log_action('UPDATE_POSTFIX_SETTINGS', 'Settings', {k: v for k, v in data.items() if k != 'password'})
    return jsonify({'success': True})


@settings_bp.route('/postfix/test', methods=['POST'])
@login_required
@permission_required('manage_settings')
def test_postfix():
    from ..notifications.email_service import send_email_postfix
    data = request.get_json() or {}
    cfg = _read_config()
    pc = cfg.get('postfix', {})

    if not pc.get('enabled') or not pc.get('host'):
        return jsonify({'error': 'Postfix is not configured'}), 400

    recipient = (data.get('recipient') or '').strip()
    if not recipient:
        return jsonify({'error': 'Test recipient is required'}), 400

    try:
        send_email_postfix(
            host=pc.get('host', 'localhost'),
            port=int(pc.get('port', 25)),
            from_address=pc.get('from_address', ''),
            use_tls=bool(pc.get('use_tls', False)),
            to_addresses=[recipient],
            subject='Wazuh Morpheus - Postfix Test',
            body='This is a test email sent via Postfix relay. Configuration is working.',
            username=pc.get('username', ''),
            password=pc.get('password', ''),
        )
        log_action('TEST_POSTFIX', 'Settings', {'recipient': recipient})
        return jsonify({'success': True, 'message': 'Test email sent via Postfix'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/notifications', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_notifications():
    data = request.get_json() or {}
    cfg = _read_config()

    notif_keys = [
        'on_exception_created', 'on_suppression_created', 'on_rule_created',
        'on_wazuh_restart_success', 'on_wazuh_restart_failure',
        'on_disk_threshold', 'disk_threshold_percent', 'on_case_ignored',
        'on_archives_no_log', 'on_indexer_issue',
        'on_bulk_ignore', 'on_bulk_suppress',
    ]
    for key in notif_keys:
        if key in data:
            val = data[key]
            if key == 'disk_threshold_percent':
                val = int(val) if val else 80
            else:
                val = bool(val)
            cfg['notifications'][key] = val

    # Save quiet hours
    if 'quiet_hours_enabled' in data:
        cfg['notifications']['quiet_hours_enabled'] = bool(data['quiet_hours_enabled'])
    if 'quiet_hours_start' in data:
        cfg['notifications']['quiet_hours_start'] = str(data['quiet_hours_start'])
    if 'quiet_hours_end' in data:
        cfg['notifications']['quiet_hours_end'] = str(data['quiet_hours_end'])

    # Save per-event recipient overrides
    event_recipients = data.get('event_recipients')
    if isinstance(event_recipients, dict):
        if 'event_recipients' not in cfg['notifications']:
            cfg['notifications']['event_recipients'] = {}
        for ev_key, addr in event_recipients.items():
            cfg['notifications']['event_recipients'][ev_key] = (addr or '').strip()

    _write_config(cfg)
    log_action('UPDATE_NOTIFICATION_SETTINGS', 'Settings', {k: v for k, v in data.items() if k != 'event_recipients'})
    return jsonify({'success': True})


@settings_bp.route('/health', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_health():
    data = request.get_json() or {}
    cfg = _read_config()
    if 'health' not in cfg:
        cfg['health'] = {}
    if 'poll_interval_seconds' in data:
        val = int(data['poll_interval_seconds'])
        cfg['health']['poll_interval_seconds'] = max(5, val)
    _write_config(cfg)
    log_action('UPDATE_HEALTH_SETTINGS', 'Settings', data)
    return jsonify({'success': True})


@settings_bp.route('/disk-mounts')
@login_required
@permission_required('manage_settings')
def disk_mounts():
    """Return available disk mount points from df."""
    import subprocess
    try:
        result = subprocess.run(
            ['df', '-h', '--output=source,target,pcent'],
            capture_output=True, text=True, timeout=5
        )
        mounts = []
        raw_lines = result.stdout.strip().split('\n')
        # Rejoin wrapped lines (df wraps long device names onto their own line)
        lines = []
        for line in raw_lines[1:]:
            parts = line.split()
            if len(parts) == 1 and lines:
                # Continuation of previous wrapped device — but could also be
                # a device-only line whose values are on the next line.
                # Peek: if previous line already has 3+ fields, this starts a new entry
                prev_parts = lines[-1].split()
                if len(prev_parts) >= 3:
                    lines.append(line)
                else:
                    lines[-1] = lines[-1] + ' ' + line
            elif len(parts) == 1:
                lines.append(line)
            else:
                if lines and len(lines[-1].split()) == 1:
                    lines[-1] = lines[-1] + ' ' + line
                else:
                    lines.append(line)
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                device = parts[0]
                try:
                    pct = int(parts[-1].replace('%', ''))
                except ValueError:
                    pct = 0
                mount = ' '.join(parts[1:-1])
                mounts.append({'device': device, 'mount': mount, 'percent': pct})
        return jsonify({'mounts': mounts})
    except Exception as e:
        return jsonify({'mounts': [], 'error': str(e)})


@settings_bp.route('/disk-thresholds', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_disk_thresholds():
    data = request.get_json() or {}
    thresholds = data.get('thresholds', [])
    if not isinstance(thresholds, list):
        return jsonify({'error': 'thresholds must be a list'}), 400

    validated = []
    for t in thresholds:
        mount = (t.get('mount') or '').strip()
        if not mount:
            continue
        validated.append({
            'mount': mount,
            'threshold': max(1, min(99, int(t.get('threshold', 80)))),
            'enabled': bool(t.get('enabled', True)),
        })

    cfg = _read_config()
    cfg['notifications']['disk_thresholds'] = validated
    _write_config(cfg)
    log_action('UPDATE_DISK_THRESHOLDS', 'Settings', {'count': len(validated)})
    return jsonify({'success': True})


@settings_bp.route('/backup', methods=['POST'])
@login_required
@permission_required('manage_backups')
def update_backup():
    data = request.get_json() or {}
    cfg = _read_config()

    if 'enabled' in data:
        cfg['backup']['enabled'] = bool(data['enabled'])
    if 'backup_dir' in data:
        bdir = str(data['backup_dir']).strip()
        if bdir and not bdir.startswith('/'):
            return jsonify({'error': 'Backup directory must be an absolute path starting with /'}), 400
        cfg['backup']['backup_dir'] = bdir
    if 'schedule_type' in data:
        cfg['backup']['schedule_type'] = data['schedule_type']
    if 'schedule_hour' in data:
        cfg['backup']['schedule_hour'] = int(data['schedule_hour'])
    if 'schedule_minute' in data:
        cfg['backup']['schedule_minute'] = int(data['schedule_minute'])
    if 'interval_hours' in data:
        cfg['backup']['interval_hours'] = int(data['interval_hours'])
    if 'interval_days' in data:
        cfg['backup']['interval_days'] = max(1, int(data['interval_days']))
    if 'schedule_days_of_week' in data:
        dow = data['schedule_days_of_week']
        if isinstance(dow, list) and dow:
            cfg['backup']['schedule_days_of_week'] = dow
    if 'compress' in data:
        cfg['backup']['compress'] = bool(data['compress'])
    if 'files_to_backup' in data:
        files = data['files_to_backup']
        if isinstance(files, str):
            files = [f.strip() for f in files.split('\n') if f.strip()]
        cfg['backup']['files_to_backup'] = files
    if 'keep_last_n' in data:
        cfg['backup']['keep_last_n'] = int(data['keep_last_n'])

    _write_config(cfg)

    # Reload scheduler
    from ..backup.service import reload_scheduler
    try:
        reload_scheduler(current_app._get_current_object())
    except Exception:
        pass

    log_action('UPDATE_BACKUP_SETTINGS', 'Settings', data)
    return jsonify({'success': True})


@settings_bp.route('/backup/trigger', methods=['POST'])
@login_required
@permission_required('manage_backups')
def trigger_backup():
    from ..backup.service import run_backup
    try:
        result = run_backup(current_app._get_current_object())
        log_action('TRIGGER_BACKUP', 'Settings', result)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/silenced-fields', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_silenced_fields():
    data = request.get_json() or {}
    fields = data.get('fields', [])
    if not isinstance(fields, list):
        return jsonify({'error': 'fields must be a list'}), 400
    cfg = _read_config()
    if 'wazuh' not in cfg:
        cfg['wazuh'] = {}
    cfg['wazuh']['silenced_fields'] = [str(f).strip() for f in fields if str(f).strip()]
    _write_config(cfg)
    log_action('UPDATE_SILENCED_FIELDS', 'Settings', {'count': len(cfg['wazuh']['silenced_fields'])})
    return jsonify({'success': True})


@settings_bp.route('/wazuh-fields', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_wazuh_fields():
    import shutil
    data = request.get_json() or {}
    raw_json = (data.get('content') or '').strip()
    if not raw_json:
        return jsonify({'error': 'Content is required'}), 400

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON: {e}'}), 400

    fields_path = os.path.join(
        current_app.config['BASE_DIR'], 'app', 'WazuhFields', 'WazuhFields.json'
    )
    os.makedirs(os.path.dirname(fields_path), exist_ok=True)

    if os.path.exists(fields_path):
        shutil.copy2(fields_path, fields_path + '.bak')

    with open(fields_path, 'w', encoding='utf-8') as f:
        json.dump(parsed, f)

    # Clear the in-memory fields cache so next request re-parses the new file
    from ..rules import routes as _rules_routes
    _rules_routes._wazuh_fields_cache = None

    log_action('UPDATE_WAZUH_FIELDS', 'Settings', {'path': fields_path})
    return jsonify({'success': True})


@settings_bp.route('/backup/history')
@login_required
@permission_required('manage_backups')
def backup_history():
    db = get_db()
    rows = db.execute(
        'SELECT * FROM backup_runs ORDER BY started_at DESC LIMIT 50'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


def _audit_filter_query(search, category, user_filter, date_from, date_to):
    """Build WHERE clause and params for audit log filtering."""
    where = ' WHERE 1=1'
    params = []
    if search:
        where += ' AND (action LIKE ? OR details LIKE ? OR username LIKE ?)'
        params.extend([f'%{search}%'] * 3)
    if category:
        where += ' AND category = ?'
        params.append(category)
    if user_filter:
        where += ' AND username = ?'
        params.append(user_filter)
    if date_from:
        where += ' AND timestamp >= ?'
        params.append(date_from)
    if date_to:
        where += ' AND timestamp <= ?'
        params.append(date_to + ' 23:59:59')
    return where, params


@settings_bp.route('/audit')
@login_required
@permission_required('view_audit_log')
def audit_log():
    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 100
    search = request.args.get('q', '').strip()
    category = request.args.get('category', '')
    user_filter = request.args.get('user', '')
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    where, params = _audit_filter_query(search, category, user_filter, date_from, date_to)

    total = db.execute(f'SELECT COUNT(*) as cnt FROM audit_log{where}', params).fetchone()['cnt']

    query = f'SELECT * FROM audit_log{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    page_params = params + [per_page, (page - 1) * per_page]
    entries = db.execute(query, page_params).fetchall()

    categories = db.execute('SELECT DISTINCT category FROM audit_log WHERE category IS NOT NULL ORDER BY category').fetchall()
    users = db.execute('SELECT DISTINCT username FROM audit_log WHERE username IS NOT NULL ORDER BY username').fetchall()

    return render_template(
        'settings/audit.html',
        entries=entries,
        total=total,
        page=page,
        per_page=per_page,
        has_next=total > page * per_page,
        search=search,
        category=category,
        user_filter=user_filter,
        date_from=date_from,
        date_to=date_to,
        categories=[r['category'] for r in categories],
        users=[r['username'] for r in users],
        active_page='settings',
        active_sub='audit'
    )


@settings_bp.route('/audit/export')
@login_required
@permission_required('view_audit_log')
def audit_export():
    """Export audit log as CSV (up to 10,000 rows)."""
    import csv
    import io

    db = get_db()
    search = request.args.get('q', '').strip()
    category = request.args.get('category', '')
    user_filter = request.args.get('user', '')
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    where, params = _audit_filter_query(search, category, user_filter, date_from, date_to)
    query = f'SELECT * FROM audit_log{where} ORDER BY timestamp DESC LIMIT 10000'
    rows = db.execute(query, params).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Username', 'Action', 'Category', 'Details', 'IP Address'])
    for r in rows:
        writer.writerow([r['id'], r['timestamp'], r['username'], r['action'],
                         r['category'], r['details'], r['ip_address']])

    log_action('EXPORT_AUDIT_LOG', 'Settings', {'rows': len(rows)})

    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=audit_log.csv'}
    )


@settings_bp.route('/audit/api')
@login_required
@permission_required('view_audit_log')
def audit_api():
    db = get_db()
    limit = request.args.get('limit', 50, type=int)
    rows = db.execute(
        'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?', (limit,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ============================================================
# Email Templates
# ============================================================

@settings_bp.route('/email-templates')
@login_required
@permission_required('manage_settings')
def list_email_templates():
    from ..notifications.email_service import EMAILS_DIR
    cfg = _read_config()
    tpl_cfg = cfg.get('email_templates', {})
    result = []
    for et in KNOWN_EVENT_TYPES:
        etc = tpl_cfg.get(et, {})
        custom_path = os.path.join(EMAILS_DIR, 'custom_emails', f'{et}.html')
        result.append({
            'event_type': et,
            'label': EVENT_LABELS.get(et, et),
            'use_custom': etc.get('use_custom', False),
            'has_custom': os.path.exists(custom_path),
            'variables': TEMPLATE_VARS.get(et, []),
        })
    return jsonify({'templates': result})


@settings_bp.route('/email-templates/<event_type>')
@login_required
@permission_required('manage_settings')
def get_email_template(event_type):
    from ..notifications.email_service import EMAILS_DIR
    if event_type not in KNOWN_EVENT_TYPES:
        return jsonify({'error': 'Unknown event type'}), 404

    default_path = os.path.join(EMAILS_DIR, f'{event_type}.html')
    custom_path = os.path.join(EMAILS_DIR, 'custom_emails', f'{event_type}.html')

    default_content = ''
    if os.path.exists(default_path):
        with open(default_path, 'r', encoding='utf-8') as f:
            default_content = f.read()

    custom_content = ''
    if os.path.exists(custom_path):
        with open(custom_path, 'r', encoding='utf-8') as f:
            custom_content = f.read()

    cfg = _read_config()
    use_custom = cfg.get('email_templates', {}).get(event_type, {}).get('use_custom', False)

    return jsonify({
        'event_type': event_type,
        'label': EVENT_LABELS.get(event_type, event_type),
        'default_content': default_content,
        'custom_content': custom_content,
        'use_custom': use_custom,
        'has_custom': bool(custom_content),
        'variables': TEMPLATE_VARS.get(event_type, []),
    })


@settings_bp.route('/email-templates/<event_type>', methods=['POST'])
@login_required
@permission_required('manage_settings')
def save_email_template(event_type):
    from ..notifications.email_service import EMAILS_DIR
    if event_type not in KNOWN_EVENT_TYPES:
        return jsonify({'error': 'Unknown event type'}), 404

    data = request.get_json() or {}
    html_content = data.get('html_content', '')
    use_custom = bool(data.get('use_custom', True))

    custom_dir = os.path.join(EMAILS_DIR, 'custom_emails')
    os.makedirs(custom_dir, exist_ok=True)

    custom_path = os.path.join(custom_dir, f'{event_type}.html')
    with open(custom_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    cfg = _read_config()
    if 'email_templates' not in cfg:
        cfg['email_templates'] = {}
    if event_type not in cfg['email_templates']:
        cfg['email_templates'][event_type] = {}
    cfg['email_templates'][event_type]['use_custom'] = use_custom

    _write_config(cfg)
    log_action('SAVE_EMAIL_TEMPLATE', 'Settings', {'event_type': event_type, 'use_custom': use_custom})
    return jsonify({'success': True})


@settings_bp.route('/email-templates/<event_type>', methods=['DELETE'])
@login_required
@permission_required('manage_settings')
def reset_email_template(event_type):
    from ..notifications.email_service import EMAILS_DIR
    if event_type not in KNOWN_EVENT_TYPES:
        return jsonify({'error': 'Unknown event type'}), 404

    custom_path = os.path.join(EMAILS_DIR, 'custom_emails', f'{event_type}.html')
    if os.path.exists(custom_path):
        os.remove(custom_path)

    cfg = _read_config()
    if 'email_templates' in cfg and event_type in cfg['email_templates']:
        cfg['email_templates'][event_type]['use_custom'] = False
    _write_config(cfg)
    log_action('RESET_EMAIL_TEMPLATE', 'Settings', {'event_type': event_type})
    return jsonify({'success': True})


@settings_bp.route('/email-templates/<event_type>/reset', methods=['POST'])
@login_required
@permission_required('manage_settings')
def reset_email_template_post(event_type):
    """POST alias for resetting a custom template (avoids needing a DELETE fetch wrapper in JS)."""
    from ..notifications.email_service import EMAILS_DIR
    if event_type not in KNOWN_EVENT_TYPES:
        return jsonify({'error': 'Unknown event type'}), 404

    custom_path = os.path.join(EMAILS_DIR, 'custom_emails', f'{event_type}.html')
    if os.path.exists(custom_path):
        os.remove(custom_path)

    cfg = _read_config()
    if 'email_templates' in cfg and event_type in cfg['email_templates']:
        cfg['email_templates'][event_type]['use_custom'] = False
    _write_config(cfg)
    log_action('RESET_EMAIL_TEMPLATE', 'Settings', {'event_type': event_type})
    return jsonify({'success': True})


@settings_bp.route('/email-templates/<event_type>/toggle', methods=['POST'])
@login_required
@permission_required('manage_settings')
def toggle_email_template(event_type):
    if event_type not in KNOWN_EVENT_TYPES:
        return jsonify({'error': 'Unknown event type'}), 404

    data = request.get_json() or {}
    use_custom = bool(data.get('use_custom', False))

    cfg = _read_config()
    if 'email_templates' not in cfg:
        cfg['email_templates'] = {}
    if event_type not in cfg['email_templates']:
        cfg['email_templates'][event_type] = {}
    cfg['email_templates'][event_type]['use_custom'] = use_custom

    _write_config(cfg)
    return jsonify({'success': True})


# ============================================================
# Indexer Monitoring
# ============================================================

@settings_bp.route('/customer-field', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_customer_field():
    data = request.get_json() or {}
    field = (data.get('field') or '').strip()
    cfg = _read_config()
    if 'alerts' not in cfg:
        cfg['alerts'] = {}
    cfg['alerts']['customer_field'] = field
    _write_config(cfg)
    log_action('UPDATE_CUSTOMER_FIELD', 'Settings', {'customer_field': field})
    return jsonify({'success': True})


@settings_bp.route('/alert-columns', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_alert_columns():
    data = request.get_json() or {}
    columns = data.get('columns', [])
    if not isinstance(columns, list):
        return jsonify({'error': 'columns must be a list'}), 400

    validated = []
    for col in columns:
        field = (col.get('field') or '').strip()
        label = (col.get('label') or '').strip()
        if not field or not label:
            return jsonify({'error': 'Each column must have a non-empty field and label'}), 400
        validated.append({'field': field, 'label': label})

    cfg = _read_config()
    if 'alerts' not in cfg:
        cfg['alerts'] = {}
    cfg['alerts']['event_columns'] = validated
    _write_config(cfg)
    log_action('UPDATE_ALERT_COLUMNS', 'Settings', {'count': len(validated)})
    return jsonify({'success': True})


@settings_bp.route('/indexers', methods=['POST'])
@login_required
@permission_required('manage_settings')
def update_indexers():
    data = request.get_json() or {}
    cfg = _read_config()

    if 'indexers' not in cfg:
        cfg['indexers'] = {'hosts': []}

    hosts = data.get('hosts')
    if isinstance(hosts, list):
        validated = []
        for h in hosts:
            name = (h.get('name') or '').strip()
            url = (h.get('url') or '').strip()
            monitor_type = h.get('type', 'cluster_health')
            if monitor_type not in ('cluster_health', 'log_activity'):
                monitor_type = 'cluster_health'
            if not name:
                return jsonify({'error': 'Each indexer must have a name'}), 400
            if not url.startswith('http://') and not url.startswith('https://'):
                return jsonify({'error': f'URL for "{name}" must start with http:// or https://'}), 400
            try:
                interval = int(float(h.get('check_interval_seconds', 120)))
            except (ValueError, TypeError):
                interval = 120
            entry = {
                'name': name,
                'url': url,
                'type': monitor_type,
                'username': (h.get('username') or '').strip(),
                'password': h.get('password', ''),
                'verify_ssl': bool(h.get('verify_ssl', False)),
                'enabled': bool(h.get('enabled', True)),
                'check_interval_seconds': max(30, interval),
            }
            if monitor_type == 'cluster_health':
                entry['alert_on'] = h.get('alert_on', 'red') if h.get('alert_on') in ('red', 'yellow', 'any') else 'red'
            elif monitor_type == 'log_activity':
                try:
                    ndm = int(float(h.get('no_new_data_minutes', 10)))
                except (ValueError, TypeError):
                    ndm = 10
                entry['no_new_data_minutes'] = max(1, ndm)
                entry['index_pattern'] = (h.get('index_pattern') or 'wazuh-alerts-*').strip()
            validated.append(entry)
        cfg['indexers']['hosts'] = validated

    _write_config(cfg)
    log_action('UPDATE_INDEXER_SETTINGS', 'Settings', {'count': len(cfg['indexers']['hosts'])})
    return jsonify({'success': True})


@settings_bp.route('/indexers/test', methods=['POST'])
@login_required
@permission_required('manage_settings')
def test_indexer():
    from ..health.indexer_monitor import _check_cluster_health, _check_latest_document
    data = request.get_json() or {}
    monitor_type = data.get('type', 'cluster_health')
    indexer = {
        'url': (data.get('url') or '').strip(),
        'username': (data.get('username') or '').strip(),
        'password': data.get('password', ''),
        'verify_ssl': bool(data.get('verify_ssl', False)),
        'index_pattern': (data.get('index_pattern') or 'wazuh-alerts-*').strip(),
    }
    if not indexer['url']:
        return jsonify({'error': 'URL is required'}), 400

    cluster = None
    doc = None
    if monitor_type == 'cluster_health':
        cluster = _check_cluster_health(indexer)
    else:
        doc = _check_latest_document(indexer)
    return jsonify({'type': monitor_type, 'cluster': cluster, 'latest_doc': doc})


# ============================================================
# Integration / Webhook
# ============================================================

@settings_bp.route('/integration')
@login_required
@permission_required('manage_integrations')
def integration():
    cfg = _read_config()
    return render_template('settings/integration.html', config=cfg,
                           active_page='settings', active_sub='integration')


@settings_bp.route('/integration/save', methods=['POST'])
@login_required
@permission_required('manage_integrations')
def integration_save():
    data = request.get_json() or {}
    cfg = _read_config()
    if 'integration' not in cfg:
        cfg['integration'] = {}

    integ = cfg['integration']
    if 'enabled' in data:
        integ['enabled'] = bool(data['enabled'])
    if 'webhook_url' in data:
        integ['webhook_url'] = str(data['webhook_url']).strip()
    if 'auth_type' in data:
        integ['auth_type'] = data['auth_type'] if data['auth_type'] in ('bearer', 'custom') else 'bearer'
    if 'auth_token' in data:
        integ['auth_token'] = str(data['auth_token'])
    if 'auth_header_name' in data:
        integ['auth_header_name'] = str(data['auth_header_name']).strip() or 'Authorization'
    if 'timeout_seconds' in data:
        integ['timeout_seconds'] = max(1, min(60, int(data['timeout_seconds'])))
    if 'retry_count' in data:
        integ['retry_count'] = max(0, min(5, int(data['retry_count'])))
    if 'resolution_options' in data:
        opts = data['resolution_options']
        if isinstance(opts, list):
            integ['resolution_options'] = [str(o).strip() for o in opts if str(o).strip()]
    if 'webhook_events' in data:
        evts = data['webhook_events']
        if isinstance(evts, dict):
            if 'webhook_events' not in integ:
                integ['webhook_events'] = {}
            for k, v in evts.items():
                integ['webhook_events'][k] = bool(v)

    _write_config(cfg)
    log_action('UPDATE_INTEGRATION_SETTINGS', 'Settings',
               {k: v for k, v in data.items() if k != 'auth_token'})
    return jsonify({'success': True})


@settings_bp.route('/integration/test', methods=['POST'])
@login_required
@permission_required('manage_integrations')
def integration_test():
    from ..notifications.webhook_service import test_webhook
    data = request.get_json() or {}
    url = (data.get('webhook_url') or '').strip()
    if not url:
        return jsonify({'error': 'Webhook URL is required'}), 400

    auth_type = data.get('auth_type', 'bearer')
    auth_token = data.get('auth_token', '')
    auth_header_name = data.get('auth_header_name', 'Authorization')

    success, status, body = test_webhook(url, auth_type, auth_token, auth_header_name)
    log_action('TEST_WEBHOOK', 'Settings', {'url': url, 'success': success, 'status': status})
    return jsonify({'success': success, 'status': status, 'body': body[:500]})


@settings_bp.route('/integration/logs')
@login_required
@permission_required('manage_integrations')
def integration_logs():
    db = get_db()
    rows = db.execute(
        'SELECT * FROM webhook_log ORDER BY created_at DESC LIMIT 100'
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@settings_bp.route('/integration/status')
@login_required
def integration_status():
    """Lightweight endpoint for alerts.js to check if integration is enabled."""
    cfg = _read_config()
    integ = cfg.get('integration', {})
    enabled = bool(integ.get('enabled'))
    return jsonify({
        'enabled': enabled,
        'resolution_options': integ.get('resolution_options', []) if enabled else [],
    })

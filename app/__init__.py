import os
import re
import json as _json
from flask import Flask, redirect, url_for, session, send_from_directory, request, jsonify, render_template


DEFAULT_CONFIG = {
    "app": {
        "secret_key": "change-this-secret-key-in-production-use-strong-random-value",
        "debug": False,
        "host": "0.0.0.0",
        "port": 5000
    },
    "database": {
        "path": "data/wazuh_platform.db"
    },
    "wazuh": {
        "alerts_json_path": "/var/ossec/logs/alerts/alerts.json",
        "default_rules_path": "/var/ossec/ruleset/rules/",
        "custom_rules_path": "/var/ossec/etc/rules/customrulesfile.xml",
        "suppressions_path": "/var/ossec/etc/rules/suppressions.xml",
        "default_rules_exceptions_path": "/var/ossec/etc/rules/default-rule-exceptions.xml",
        "archives_json_path": "",
        "no_log_alert_seconds": 300,
        "silenced_fields": [
            "rule.level", "rule.groups", "data.win.system.processID",
            "rule.mitre.technique", "data.win.system.threadID", "rule.id",
            "agent.labels.Customer", "manager.name", "decoder.name",
            "data.win.system.channel", "data.win.system.severityValue", "id",
            "rule.firedtimes", "location", "rule.mail", "cluster.name",
            "rule.mitre.tactic", "rule.mitre.id", "rule.gpg13", "rule.tsc",
            "cluster.node", "rule.pci_dss", "rule.gdpr", "rule.nist_800_53",
            "rule.hipaa"
        ]
    },
    "postfix": {
        "enabled": False,
        "host": "localhost",
        "port": 25,
        "from_address": "",
        "username": "",
        "password": "",
        "use_tls": False
    },
    "email": {
        "enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "smtp_tls": True,
        "from_address": "",
        "recipients": ""
    },
    "notifications": {
        "on_exception_created": True,
        "on_suppression_created": True,
        "on_rule_created": True,
        "on_wazuh_restart_success": True,
        "on_wazuh_restart_failure": True,
        "on_disk_threshold": True,
        "disk_threshold_percent": 80,
        "on_case_ignored": True,
        "on_archives_no_log": True,
        "on_indexer_issue": True,
        "on_bulk_ignore": True,
        "on_bulk_suppress": True,
        "quiet_hours_enabled": False,
        "quiet_hours_start": "00:00",
        "quiet_hours_end": "06:00",
        "disk_thresholds": [],
        "event_recipients": {
            "on_exception_created": "",
            "on_suppression_created": "",
            "on_rule_created": "",
            "on_wazuh_restart_success": "",
            "on_wazuh_restart_failure": "",
            "on_disk_threshold": "",
            "on_case_ignored": "",
            "on_archives_no_log": "",
            "on_indexer_issue": ""
        }
    },
    "email_templates": {
        "exception_created": {"use_custom": False},
        "suppression_created": {"use_custom": False},
        "rule_created": {"use_custom": False},
        "wazuh_restart_success": {"use_custom": False},
        "wazuh_restart_failure": {"use_custom": False},
        "disk_threshold": {"use_custom": False},
        "case_ignored": {"use_custom": False},
        "archives_no_log": {"use_custom": False},
        "indexer_issue": {"use_custom": False},
        "bulk_ignore": {"use_custom": False},
        "bulk_suppress": {"use_custom": False}
    },
    "indexers": {
        "hosts": []
    },
    "alerts": {
        "customer_field": "",
        "event_columns": [
            {"field": "timestamp", "label": "Timestamp"},
            {"field": "agent.name", "label": "Endpoint"},
            {"field": "agent.ip", "label": "IP Address"}
        ]
    },
    "health": {
        "poll_interval_seconds": 30
    },
    "integration": {
        "enabled": False,
        "webhook_url": "",
        "auth_type": "bearer",
        "auth_token": "",
        "auth_header_name": "Authorization",
        "timeout_seconds": 10,
        "retry_count": 2,
        "resolution_options": ["False Positive", "True Positive", "Benign Positive", "Informational"],
        "webhook_events": {
            "case_ignored": True,
            "exception_created": True,
            "suppression_created": True,
            "bulk_ignore": True,
            "bulk_suppress": True
        }
    },
    "backup": {
        "enabled": False,
        "backup_dir": "",
        "schedule_type": "daily",
        "schedule_hour": 23,
        "schedule_minute": 59,
        "interval_hours": 24,
        "interval_days": 2,
        "schedule_days_of_week": ["mon", "wed", "fri"],
        "compress": True,
        "files_to_backup": [
            "/var/ossec/etc/rules/customrulesfile.xml",
            "/var/ossec/etc/rules/suppressions.xml",
            "/var/ossec/etc/rules/default_rules_exceptions.xml"
        ],
        "keep_last_n": 30
    }
}


def _create_default_config(path):
    """Create a default config.json when none exists."""
    import logging
    logger = logging.getLogger(__name__)
    with open(path, 'w', encoding='utf-8') as f:
        _json.dump(DEFAULT_CONFIG, f, indent=2)
    logger.info(f'Created default config.json at {path}')


def create_app():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(
        __name__,
        template_folder=os.path.join(base_dir, 'templates'),
        static_folder=os.path.join(base_dir, 'static')
    )

    config_path = os.path.join(base_dir, 'config.json')
    if not os.path.exists(config_path):
        _create_default_config(config_path)
    with open(config_path) as f:
        config = _json.load(f)

    app.secret_key = config['app']['secret_key']
    app.config['DEBUG'] = config['app'].get('debug', False)
    app.config['CONFIG'] = config
    app.config['CONFIG_PATH'] = config_path
    app.config['BASE_DIR'] = base_dir
    app.config['DB_PATH'] = os.path.join(base_dir, config['database']['path'])

    os.makedirs(os.path.dirname(app.config['DB_PATH']), exist_ok=True)

    from .database import init_db
    init_db(app)

    from .auth.routes import auth_bp
    from .alerts.routes import alerts_bp
    from .rules.routes import rules_bp
    from .health.routes import health_bp
    from .settings.routes import settings_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(alerts_bp, url_prefix='/alerts')
    app.register_blueprint(rules_bp, url_prefix='/rules')
    app.register_blueprint(health_bp, url_prefix='/health')
    app.register_blueprint(settings_bp, url_prefix='/settings')

    @app.route('/')
    def index():
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return redirect(url_for('alerts.cases_list'))

    @app.errorhandler(403)
    def forbidden(e):
        if request.accept_mimetypes.accept_json and \
           not request.accept_mimetypes.accept_html:
            return jsonify({'error': 'Permission denied'}), 403
        return render_template('errors/403.html', active_page=''), 403

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(
            os.path.join(app.static_folder, 'img'),
            'icon.png',
            mimetype='image/png'
        )

    # ----------------------------------------------------------------
    # Jinja2 custom filters
    # ----------------------------------------------------------------

    @app.template_filter('fromjson')
    def fromjson_filter(s):
        if not s:
            return []
        try:
            return _json.loads(s)
        except Exception:
            return []

    @app.template_filter('pretty_json')
    def pretty_json_filter(s):
        if not s:
            return ''
        try:
            return _json.dumps(_json.loads(s), indent=2)
        except Exception:
            return str(s)

    @app.template_filter('flatten_dict')
    def flatten_dict_filter(d, _prefix=''):
        from flask import current_app as _ca
        silenced = set(
            _ca.config.get('CONFIG', {}).get('wazuh', {}).get('silenced_fields', [])
        )

        def _clean_key(k):
            # Strip all whitespace (including embedded \r\n from Wazuh XML parsing)
            return re.sub(r'\s+', '', str(k))

        def _clean_val(v):
            # Remove embedded newlines/carriage-returns that render as spaces in HTML
            s = str(v) if v is not None else ''
            return re.sub(r'[\r\n]+', '', s)

        result = []
        if not isinstance(d, dict):
            return result
        for key, value in d.items():
            clean = _clean_key(key)
            full_key = (_prefix + '.' + clean) if _prefix else clean
            if full_key in silenced:
                continue
            if isinstance(value, dict):
                result.extend(flatten_dict_filter(value, full_key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        result.extend(flatten_dict_filter(item, full_key + '[' + str(i) + ']'))
                    else:
                        result.append((full_key + '[' + str(i) + ']', _clean_val(item)))
            else:
                result.append((full_key, _clean_val(value)))
        return result

    @app.template_filter('rows_to_dicts')
    def rows_to_dicts_filter(rows):
        try:
            return [dict(r) for r in rows]
        except Exception:
            return list(rows)

    @app.template_filter('resolve_event_col')
    def resolve_event_col_filter(item, field):
        """Resolve a dot-path field from an event item dict.

        Shortcut mappings for DB columns:
          timestamp  -> item['event']['timestamp'][:19]
          agent.name -> item['event']['agent_name']
          agent.ip   -> item['event']['agent_ip']
          agent.id   -> item['event']['agent_id']
        Otherwise walk item['parsed'] by dot-separated keys.
        """
        _shortcuts = {
            'timestamp': lambda ev: (ev.get('timestamp') or '')[:19],
            'agent.name': lambda ev: ev.get('agent_name') or ev.get('agent_id') or '',
            'agent.ip': lambda ev: ev.get('agent_ip') or '',
            'agent.id': lambda ev: ev.get('agent_id') or '',
        }
        ev = item.get('event', {}) if isinstance(item, dict) else {}
        if field in _shortcuts:
            val = _shortcuts[field](ev)
            return val if val else '-'
        parsed = item.get('parsed', {}) if isinstance(item, dict) else {}
        parts = field.split('.')
        obj = parsed
        for p in parts:
            if isinstance(obj, dict):
                obj = obj.get(p)
            else:
                return '-'
            if obj is None:
                return '-'
        return str(obj) if obj is not None else '-'

    from .alerts.tailer import start_tailer
    start_tailer(app)

    from .alerts.archives_tailer import start_archives_tailer
    start_archives_tailer(app)

    from .health.indexer_monitor import start_indexer_monitor
    start_indexer_monitor(app)

    from .backup.service import init_backup_scheduler
    init_backup_scheduler(app)

    return app

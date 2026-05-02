import json
import os
import re
from datetime import datetime
from flask import (Blueprint, render_template, request, jsonify, session,
                   abort, current_app)
from ..database import get_db
from ..auth.decorators import login_required, permission_required
from ..audit.logger import log_action
from ..notifications.email_service import send_notification
from ..notifications.webhook_service import is_integration_enabled, get_resolution_options, fire_webhook
from . import parser as rule_parser
from . import builder as rule_builder

rules_bp = Blueprint('rules', __name__)

# Wazuh predefined static fields — these live under data.* in alert JSON but
# must keep the "data." prefix in <field name="..."> because stripping it
# would produce a bare static-field name that Wazuh rejects.
_WAZUH_STATIC_FIELDS = frozenset([
    'user', 'srcip', 'dstip', 'srcport', 'dstport', 'protocol', 'action',
    'id', 'url', 'data', 'extra_data', 'status', 'system_name',
    'srcuser', 'dstuser',
])


def _normalize_field_name(name):
    """Convert an alert-JSON field path to the correct Wazuh rule field name.

    Dynamic fields: data.win.system.eventID -> win.system.eventID  (strip data.)
    Static fields:  data.srcuser            -> data.srcuser        (keep data.)
    """
    stripped = re.sub(r'^data\.', '', name)
    if stripped == name:
        return name  # no data. prefix — return as-is
    if stripped in _WAZUH_STATIC_FIELDS:
        return name  # static field — keep data. prefix
    return stripped


def _cfg():
    return current_app.config['CONFIG']['wazuh']


# ---------------------------------------------------------------------------
# Rule browsing
# ---------------------------------------------------------------------------

@rules_bp.route('/')
@login_required
@permission_required('view_rules')
def rules_list():
    cfg = _cfg()
    source = request.args.get('source', 'all')
    search = request.args.get('q', '').strip()
    sort_by = request.args.get('sort_by', '')
    sort_dir = request.args.get('sort_dir', 'asc')
    page = request.args.get('page', 1, type=int)
    per_page = 0 if request.args.get('all') else 100
    suppressed_ids = set()
    exception_ids = set()

    try:
        if source == 'all':
            custom_rules = rule_parser.parse_rules_from_file(cfg['custom_rules_path'])
            for r in custom_rules:
                r['rule_source'] = 'custom'
            default_rules = rule_parser.parse_rules_from_directory(cfg['default_rules_path'])
            for r in default_rules:
                r['rule_source'] = 'default'
            rules = custom_rules + default_rules
            # Badge data for custom rules
            for r in custom_rules:
                if str(r.get('level', '')) == '0':
                    suppressed_ids.add(r['id'])
                if any(f.get('negate') for f in r.get('fields', [])):
                    exception_ids.add(r['id'])
            # Badge data for default rules
            try:
                _sup = rule_parser.parse_rules_from_file(cfg['suppressions_path'])
                suppressed_ids.update({r['id'] for r in _sup})
            except Exception:
                pass
            try:
                _exc = rule_parser.parse_rules_from_file(cfg['default_rules_exceptions_path'])
                exception_ids.update({r['id'] for r in _exc})
            except Exception:
                pass
        elif source == 'exceptions':
            rules = rule_parser.parse_rules_from_file(cfg['default_rules_exceptions_path'])
            for r in rules:
                r['rule_source'] = 'default'
        elif source == 'suppressions':
            rules = rule_parser.parse_rules_from_file(cfg['suppressions_path'])
            for r in rules:
                r['rule_source'] = 'default'
        else:
            # Fallback: treat unknown as 'all'
            rules = []

        if search:
            rules = [r for r in rules if
                     search.lower() in r.get('id', '').lower() or
                     search.lower() in r.get('description', '').lower()]

        if sort_by:
            reverse = (sort_dir == 'desc')
            if sort_by == 'id':
                rules.sort(key=lambda r: int(r['id']) if str(r.get('id', '')).isdigit() else 0, reverse=reverse)
            elif sort_by == 'level':
                rules.sort(key=lambda r: int(r['level']) if str(r.get('level', '')).isdigit() else 0, reverse=reverse)
            elif sort_by == 'source':
                rules.sort(key=lambda r: r.get('rule_source', ''), reverse=reverse)
            else:
                rules.sort(key=lambda r: r.get('description', '').lower(), reverse=reverse)

        total = len(rules)
        if per_page:
            rules_page = rules[(page - 1) * per_page: page * per_page]
        else:
            rules_page = rules
        error = None
    except Exception as e:
        rules_page = []
        total = 0
        error = str(e)

    total_pages = ((total + per_page - 1) // per_page) if per_page else 1

    return render_template(
        'rules/list.html',
        rules=rules_page,
        source=source,
        search=search,
        sort_by=sort_by,
        sort_dir=sort_dir,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        has_next=per_page > 0 and total > page * per_page,
        suppressed_ids=suppressed_ids,
        exception_ids=exception_ids,
        error=error,
        active_page='rules'
    )


@rules_bp.route('/view/<source>/<rule_id>')
@login_required
@permission_required('view_rules')
def view_rule(source, rule_id):
    cfg = _cfg()
    try:
        if source == 'custom':
            rules = rule_parser.parse_rules_from_file(cfg['custom_rules_path'])
        elif source == 'default':
            rules = rule_parser.parse_rules_from_directory(cfg['default_rules_path'])
        elif source == 'exceptions':
            rules = rule_parser.parse_rules_from_file(cfg['default_rules_exceptions_path'])
        elif source == 'suppressions':
            rules = rule_parser.parse_rules_from_file(cfg['suppressions_path'])
        else:
            abort(404)

        rule = next((r for r in rules if r['id'] == rule_id), None)
        if not rule:
            abort(404)

        # Get existing actions for this rule
        db = get_db()
        actions = db.execute(
            '''SELECT ra.*, u.username as author FROM rule_actions ra
               LEFT JOIN users u ON u.id = ra.created_by
               WHERE ra.rule_id = ? ORDER BY ra.created_at DESC''',
            (rule_id,)
        ).fetchall()

        return render_template(
            'rules/detail.html',
            rule=rule,
            source=source,
            actions=actions,
            active_page='rules'
        )
    except Exception as e:
        abort(500)


# ---------------------------------------------------------------------------
# Custom rule creation
# ---------------------------------------------------------------------------

@rules_bp.route('/create', methods=['GET', 'POST'])
@login_required
@permission_required('create_custom_rules')
def create_rule():
    cfg = _cfg()
    if request.method == 'GET':
        next_id = rule_builder.get_next_custom_rule_id(cfg['custom_rules_path'])
        return render_template('rules/create.html', next_id=next_id, active_page='rules', active_sub='create')

    data = request.get_json() or request.form.to_dict()

    try:
        rule_id = int(data.get('id', 0))
        if rule_id < 100000:
            return jsonify({'error': 'Custom rule IDs must be >= 100000'}), 400

        rule_data = {
            'id': rule_id,
            'level': int(data.get('level', 8)),
            'description': data.get('description', ''),
            'if_sid': data.get('if_sid', ''),
            'if_group': data.get('if_group', ''),
            'match': data.get('match', ''),
            'match_type': data.get('match_type', 'pcre2'),
            'regex': data.get('regex', ''),
            'regex_type': data.get('regex_type', 'pcre2'),
            'fields': [
                {**f, 'name': _normalize_field_name(f.get('name', ''))}
                for f in (json.loads(data.get('fields', '[]')) if isinstance(data.get('fields'), str) else data.get('fields', []))
            ],
            'mitre_ids': json.loads(data.get('mitre_ids', '[]')) if isinstance(data.get('mitre_ids'), str) else data.get('mitre_ids', []),
            'options': json.loads(data.get('options', '[]')) if isinstance(data.get('options'), str) else data.get('options', []),
            'groups': json.loads(data.get('groups', '[]')) if isinstance(data.get('groups'), str) else data.get('groups', []),
            'frequency': data.get('frequency'),
            'timeframe': data.get('timeframe'),
            'ignore': data.get('ignore'),
        }

        diff = rule_builder.create_custom_rule(cfg['custom_rules_path'], rule_data)

        db = get_db()
        db.execute(
            '''INSERT INTO rule_actions
               (action_type, rule_id, rule_source, target_file, full_xml, created_by, notes, diff_after)
               VALUES ('custom_rule', ?, 'custom', ?, ?, ?, ?, ?)''',
            (str(rule_id), cfg['custom_rules_path'],
             _get_rule_xml_from_file(cfg['custom_rules_path'], rule_id),
             session['user_id'], rule_data['description'], diff)
        )
        db.commit()

        log_action('CREATE_RULE', 'Rules', {'rule_id': rule_id, 'level': rule_data['level'],
                                             'description': rule_data['description']})
        _raw_xml = _get_rule_xml_from_file(cfg['custom_rules_path'], rule_id)
        send_notification('rule_created', {
            'rule_id': rule_id,
            'description': rule_data['description'],
            'level': rule_data['level'],
            'if_sid': rule_data.get('if_sid', ''),
            'groups': ', '.join(rule_data.get('groups', [])) if rule_data.get('groups') else '',
            'match': rule_data.get('match', ''),
            'match_type': rule_data.get('match_type', ''),
            'frequency': rule_data.get('frequency', ''),
            'timeframe': rule_data.get('timeframe', ''),
            'raw_xml': _raw_xml or '',
            'created_by': session['username'],
        })

        return jsonify({'success': True, 'rule_id': rule_id, 'diff': diff})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

@rules_bp.route('/exceptions')
@login_required
@permission_required('view_exceptions')
def exceptions_list():
    cfg = _cfg()
    active_tab = request.args.get('tab', 'custom')
    sort_by  = request.args.get('sort_by', 'rule_id')
    sort_dir = request.args.get('sort_dir', 'asc')
    search   = request.args.get('q', '').strip()
    page     = request.args.get('page', 1, type=int)
    per_page = 0 if request.args.get('all') else 100

    def _sort_rules(rules, key='rule_id'):
        reverse = (sort_dir == 'desc')
        if key == 'rule_id':
            rules.sort(key=lambda r: int(r['id']) if str(r.get('id', '')).isdigit() else 0, reverse=reverse)
        elif key == 'level':
            rules.sort(key=lambda r: int(r['level']) if str(r.get('level', '')).isdigit() else 0, reverse=reverse)
        else:
            rules.sort(key=lambda r: r.get('description', '').lower(), reverse=reverse)

    def _sort_exc(items, key='rule_id'):
        reverse = (sort_dir == 'desc')
        if key == 'rule_id':
            items.sort(key=lambda x: int(x['rule']['id']) if str(x['rule'].get('id', '')).isdigit() else 0, reverse=reverse)
        elif key == 'level':
            items.sort(key=lambda x: int(x['rule']['level']) if str(x['rule'].get('level', '')).isdigit() else 0, reverse=reverse)
        else:
            items.sort(key=lambda x: x['rule'].get('description', '').lower(), reverse=reverse)

    try:
        custom_exceptions = _get_exceptions_from_custom_rules(cfg['custom_rules_path'])
        default_exceptions = rule_parser.parse_rules_from_file(cfg['default_rules_exceptions_path'])

        if search:
            sq = search.lower()
            custom_exceptions = [x for x in custom_exceptions if
                                  sq in x['rule'].get('id', '').lower() or
                                  sq in x['rule'].get('description', '').lower()]
            default_exceptions = [r for r in default_exceptions if
                                   sq in r.get('id', '').lower() or
                                   sq in r.get('description', '').lower()]

        _sort_exc(custom_exceptions, sort_by)
        _sort_rules(default_exceptions, sort_by)
        error = None
    except Exception as e:
        custom_exceptions = []
        default_exceptions = []
        error = str(e)

    db = get_db()
    actions = db.execute(
        '''SELECT ra.*, u.username as author FROM rule_actions ra
           LEFT JOIN users u ON u.id = ra.created_by
           WHERE ra.action_type IN ('exception_custom', 'exception_default', 'DELETE_EXCEPTION')
           ORDER BY ra.created_at DESC LIMIT 200'''
    ).fetchall()

    # Paginate the active tab's data
    if active_tab == 'custom':
        total = len(custom_exceptions)
        if per_page:
            custom_exceptions = custom_exceptions[(page - 1) * per_page: page * per_page]
    else:
        total = len(default_exceptions)
        if per_page:
            default_exceptions = default_exceptions[(page - 1) * per_page: page * per_page]

    total_pages = ((total + per_page - 1) // per_page) if per_page else 1

    return render_template(
        'rules/exceptions.html',
        custom_exceptions=custom_exceptions,
        default_exceptions=default_exceptions,
        actions=actions,
        error=error,
        active_tab=active_tab,
        sort_by=sort_by,
        sort_dir=sort_dir,
        search=search,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        active_page='rules',
        active_sub='exceptions'
    )


@rules_bp.route('/exceptions/create', methods=['POST'])
@login_required
def create_exception():
    data = request.get_json() or {}
    rule_id = str(data.get('rule_id', ''))
    field_name = _normalize_field_name(str(data.get('field_name', '')))
    match_type = data.get('match_type', 'pcre2')
    case_id = data.get('case_id')
    notes = (data.get('notes') or '').strip()
    if not notes:
        return jsonify({'error': 'Notes are required'}), 400

    resolution = (data.get('resolution') or '').strip()
    if is_integration_enabled():
        if not resolution or resolution not in get_resolution_options():
            return jsonify({'error': 'Valid resolution is required'}), 400

    # Accept field_values (array of values) OR field_value (single/pipe-joined string)
    field_values_list = data.get('field_values')
    if field_values_list and isinstance(field_values_list, list):
        field_value = '|'.join(str(v) for v in field_values_list if str(v).strip())
    else:
        field_value = str(data.get('field_value', '')).strip()

    # Auto-classify: IDs below 100,000 are default (built-in) Wazuh rules.
    try:
        rule_source = 'default' if int(rule_id) < 100000 else 'custom'
    except (ValueError, TypeError):
        rule_source = 'custom'

    if not rule_id or not field_name or not field_value:
        return jsonify({'error': 'rule_id, field_name, and field_value are required'}), 400

    # Permission check based on source
    perm = 'create_default_exceptions' if rule_source == 'default' else 'create_custom_exceptions'
    from ..auth.decorators import has_permission
    if not has_permission(session['user_id'], perm):
        return jsonify({'error': 'Permission denied'}), 403

    cfg = _cfg()
    try:
        if rule_source == 'custom':
            diff = rule_builder.add_exception_to_custom_rule(
                cfg['custom_rules_path'], rule_id, field_name, field_value, match_type
            )
            target_file = cfg['custom_rules_path']
            action_type = 'exception_custom'
        else:
            diff = rule_builder.add_exception_to_default_rule(
                cfg['default_rules_exceptions_path'],
                cfg['default_rules_path'],
                rule_id, field_name, field_value, match_type
            )
            target_file = cfg['default_rules_exceptions_path']
            action_type = 'exception_default'

        db = get_db()
        db.execute(
            '''INSERT INTO rule_actions
               (action_type, rule_id, rule_source, target_file, field_name, field_value,
                match_type, is_negate, case_id, created_by, notes, diff_after)
               VALUES (?,?,?,?,?,?,?,1,?,?,?,?)''',
            (action_type, rule_id, rule_source, target_file,
             field_name, field_value, match_type, case_id,
             session['user_id'], notes, diff)
        )

        # Close the associated case if provided
        if case_id:
            db.execute(
                '''UPDATE alert_cases SET status = 'excepted',
                   closed_at = datetime('now'), closed_by = ? WHERE id = ?''',
                (session['user_id'], case_id)
            )

        db.commit()

        log_action('CREATE_EXCEPTION', 'Rules', {
            'rule_id': rule_id, 'rule_source': rule_source,
            'field_name': field_name, 'field_value': field_value,
            'match_type': match_type, 'case_id': case_id
        })
        _rule_desc, _rule_level = _lookup_rule_description(rule_id, rule_source, cfg)
        send_notification('exception_created', {
            'rule_id': rule_id,
            'rule_source': rule_source,
            'rule_description': _rule_desc,
            'rule_level': _rule_level,
            'field_name': field_name,
            'field_value': field_value,
            'match_type': match_type,
            'created_by': session['username'],
            'notes': notes,
        })
        if is_integration_enabled():
            _customer = ''
            _user_email = ''
            if case_id:
                _case_row = db.execute('SELECT customer FROM alert_cases WHERE id = ?', (case_id,)).fetchone()
                if _case_row:
                    _customer = _case_row['customer'] or ''
            _u_row = db.execute('SELECT email FROM users WHERE username = ?', (session.get('username', ''),)).fetchone()
            if _u_row:
                _user_email = _u_row['email'] or ''
            fire_webhook('exception_created', {
                'action': 'exception_created',
                'rule_id': rule_id,
                'rule_description': _rule_desc,
                'notes': notes,
                'resolution': resolution,
                'username': session.get('username', ''),
                'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
                'case_id': case_id,
                'field_name': field_name,
                'field_value': field_value,
                'customer': _customer,
                'user_email': _user_email,
            }, current_app._get_current_object())

        return jsonify({'success': True, 'diff': diff})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/exceptions/delete', methods=['POST'])
@login_required
@permission_required('delete_exceptions')
def delete_exception():
    data = request.get_json() or {}
    rule_id = str(data.get('rule_id', ''))
    rule_source = data.get('rule_source', 'custom')
    field_name = data.get('field_name', '')
    field_value = data.get('field_value', '')

    cfg = _cfg()
    try:
        if rule_source == 'custom':
            file_path = cfg['custom_rules_path']
        else:
            file_path = cfg['default_rules_exceptions_path']

        diff = rule_builder.delete_exception_from_file(file_path, rule_id, field_name, field_value)

        log_action('DELETE_EXCEPTION', 'Rules', {
            'rule_id': rule_id, 'field_name': field_name, 'field_value': field_value
        })
        return jsonify({'success': True, 'diff': diff})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/delete', methods=['POST'])
@login_required
def delete_rule():
    from ..auth.decorators import has_permission
    data = request.get_json() or {}
    rule_id = str(data.get('rule_id', ''))
    rule_source = data.get('rule_source', 'custom')
    notes = (data.get('notes') or '').strip()

    if not rule_id:
        return jsonify({'error': 'rule_id is required'}), 400
    if not notes:
        return jsonify({'error': 'Notes are required'}), 400

    # Check source-specific permission
    perm_map = {
        'custom': 'delete_custom_rules',
        'default_exception': 'delete_exceptions',
        'suppression': 'delete_suppressions',
    }
    required_perm = perm_map.get(rule_source)
    if not required_perm:
        return jsonify({'error': 'Invalid rule_source'}), 400

    if not session.get('is_root') and not has_permission(session['user_id'], required_perm):
        return jsonify({'error': 'Permission denied'}), 403

    cfg = _cfg()
    try:
        if rule_source == 'custom':
            file_path = cfg['custom_rules_path']
        elif rule_source == 'default_exception':
            file_path = cfg['default_rules_exceptions_path']
        elif rule_source == 'suppression':
            file_path = cfg['suppressions_path']
        else:
            return jsonify({'error': 'Invalid rule_source'}), 400

        diff = rule_builder.delete_rule_from_file(file_path, rule_id)

        db = get_db()
        db.execute(
            '''INSERT INTO rule_actions
               (action_type, rule_id, rule_source, target_file, created_by, notes, diff_after)
               VALUES (?,?,?,?,?,?,?)''',
            ('delete_rule', rule_id, rule_source, file_path, session['user_id'], notes, diff)
        )
        db.commit()

        log_action('DELETE_RULE', 'Rules', {
            'rule_id': rule_id, 'rule_source': rule_source, 'notes': notes
        })
        return jsonify({'success': True, 'diff': diff})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------

@rules_bp.route('/suppressions')
@login_required
@permission_required('view_suppressions')
def suppressions_list():
    cfg = _cfg()
    active_tab = request.args.get('tab', 'custom')
    search = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 0 if request.args.get('all') else 100
    try:
        custom_suppressions = _get_suppressions_from_custom_rules(cfg['custom_rules_path'])
        default_suppressions = rule_parser.parse_rules_from_file(cfg['suppressions_path'])

        if search:
            sq = search.lower()
            custom_suppressions = [r for r in custom_suppressions if
                                    sq in r.get('id', '').lower() or
                                    sq in r.get('description', '').lower()]
            default_suppressions = [r for r in default_suppressions if
                                     sq in r.get('id', '').lower() or
                                     sq in r.get('description', '').lower()]

        error = None
    except Exception as e:
        custom_suppressions = []
        default_suppressions = []
        error = str(e)

    if active_tab == 'custom':
        total = len(custom_suppressions)
        if per_page:
            custom_suppressions = custom_suppressions[(page - 1) * per_page: page * per_page]
    else:
        total = len(default_suppressions)
        if per_page:
            default_suppressions = default_suppressions[(page - 1) * per_page: page * per_page]

    total_pages = ((total + per_page - 1) // per_page) if per_page else 1

    db = get_db()
    actions = db.execute(
        '''SELECT ra.*, u.username as author FROM rule_actions ra
           LEFT JOIN users u ON u.id = ra.created_by
           WHERE ra.action_type IN ('suppression_custom', 'suppression_default')
           ORDER BY ra.created_at DESC LIMIT 200'''
    ).fetchall()

    return render_template(
        'rules/suppressions.html',
        custom_suppressions=custom_suppressions,
        default_suppressions=default_suppressions,
        actions=actions,
        error=error,
        active_tab=active_tab,
        search=search,
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        active_page='rules',
        active_sub='suppressions'
    )


@rules_bp.route('/suppressions/create', methods=['POST'])
@login_required
def create_suppression():
    data = request.get_json() or {}
    rule_id = str(data.get('rule_id', ''))
    case_id = data.get('case_id')
    notes = (data.get('notes') or '').strip()
    if not notes:
        return jsonify({'error': 'Notes are required'}), 400

    resolution = (data.get('resolution') or '').strip()
    if is_integration_enabled():
        if not resolution or resolution not in get_resolution_options():
            return jsonify({'error': 'Valid resolution is required'}), 400

    # Auto-classify: IDs below 100,000 are default (built-in) Wazuh rules.
    try:
        rule_source = 'default' if int(rule_id) < 100000 else 'custom'
    except (ValueError, TypeError):
        rule_source = 'custom'

    if not rule_id:
        return jsonify({'error': 'rule_id is required'}), 400

    perm = 'create_default_suppressions' if rule_source == 'default' else 'create_custom_suppressions'
    from ..auth.decorators import has_permission
    if not has_permission(session['user_id'], perm):
        return jsonify({'error': 'Permission denied'}), 403

    cfg = _cfg()
    try:
        if rule_source == 'custom':
            # Check if already suppressed (level 0)
            existing = rule_parser.parse_rules_from_file(cfg['custom_rules_path'])
            match = next((r for r in existing if r['id'] == rule_id), None)
            if match and str(match.get('level', '')) == '0':
                return jsonify({'error': f'Rule {rule_id} is already suppressed'}), 409
            diff = rule_builder.suppress_custom_rule(cfg['custom_rules_path'], rule_id)
            target_file = cfg['custom_rules_path']
            action_type = 'suppression_custom'
        else:
            diff = rule_builder.suppress_default_rule(
                cfg['suppressions_path'], cfg['default_rules_path'], rule_id
            )
            target_file = cfg['suppressions_path']
            action_type = 'suppression_default'

        db = get_db()
        db.execute(
            '''INSERT INTO rule_actions
               (action_type, rule_id, rule_source, target_file, case_id, created_by, notes, diff_after)
               VALUES (?,?,?,?,?,?,?,?)''',
            (action_type, rule_id, rule_source, target_file,
             case_id, session['user_id'], notes, diff)
        )

        if case_id:
            db.execute(
                '''UPDATE alert_cases SET status = 'suppressed',
                   closed_at = datetime('now'), closed_by = ? WHERE id = ?''',
                (session['user_id'], case_id)
            )

        db.commit()

        log_action('CREATE_SUPPRESSION', 'Rules', {
            'rule_id': rule_id, 'rule_source': rule_source, 'case_id': case_id
        })
        _rule_desc, _rule_level = _lookup_rule_description(rule_id, rule_source, cfg)
        send_notification('suppression_created', {
            'rule_id': rule_id,
            'rule_source': rule_source,
            'rule_description': _rule_desc,
            'rule_level': _rule_level,
            'created_by': session['username'],
            'notes': notes,
        })
        if is_integration_enabled():
            _customer = ''
            _user_email = ''
            if case_id:
                _case_row = db.execute('SELECT customer FROM alert_cases WHERE id = ?', (case_id,)).fetchone()
                if _case_row:
                    _customer = _case_row['customer'] or ''
            _u_row = db.execute('SELECT email FROM users WHERE username = ?', (session.get('username', ''),)).fetchone()
            if _u_row:
                _user_email = _u_row['email'] or ''
            fire_webhook('suppression_created', {
                'action': 'suppression_created',
                'rule_id': rule_id,
                'rule_description': _rule_desc,
                'notes': notes,
                'resolution': resolution,
                'username': session.get('username', ''),
                'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
                'case_id': case_id,
                'customer': _customer,
                'user_email': _user_email,
            }, current_app._get_current_object())

        return jsonify({'success': True, 'diff': diff})
    except ValueError as e:
        if 'ALREADY_SUPPRESSED' in str(e):
            return jsonify({'error': f'Rule {rule_id} is already suppressed'}), 409
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/suppressions/restore', methods=['POST'])
@login_required
def restore_suppression():
    data = request.get_json() or {}
    rule_id = str(data.get('rule_id', ''))
    new_level = data.get('new_level')
    notes = (data.get('notes') or '').strip()

    if not rule_id:
        return jsonify({'error': 'rule_id is required'}), 400
    if not notes:
        return jsonify({'error': 'Notes are required'}), 400

    try:
        rule_source = 'default' if int(rule_id) < 100000 else 'custom'
    except (ValueError, TypeError):
        rule_source = 'custom'

    perm = 'create_default_suppressions' if rule_source == 'default' else 'create_custom_suppressions'
    from ..auth.decorators import has_permission
    if not has_permission(session['user_id'], perm):
        return jsonify({'error': 'Permission denied'}), 403

    cfg = _cfg()
    try:
        if rule_source == 'custom':
            if new_level is None:
                return jsonify({'error': 'new_level is required for custom rule restore'}), 400
            diff = rule_builder.restore_custom_rule(cfg['custom_rules_path'], rule_id, int(new_level))
            target_file = cfg['custom_rules_path']
        else:
            diff = rule_builder.restore_default_rule(cfg['suppressions_path'], rule_id)
            target_file = cfg['suppressions_path']

        db = get_db()
        db.execute(
            '''INSERT INTO rule_actions
               (action_type, rule_id, rule_source, target_file, created_by, notes, diff_after)
               VALUES (?,?,?,?,?,?,?)''',
            ('restore_suppression', rule_id, rule_source, target_file,
             session['user_id'], notes, diff)
        )
        db.commit()

        log_action('RESTORE_SUPPRESSION', 'Rules', {
            'rule_id': rule_id, 'rule_source': rule_source,
            'new_level': new_level if rule_source == 'custom' else None
        })

        return jsonify({'success': True, 'diff': diff})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/suppressions/bulk', methods=['POST'])
@login_required
@permission_required('bulk_actions')
def bulk_suppress():
    data = request.get_json() or {}
    rule_ids = data.get('rule_ids', [])
    notes = data.get('notes', '')

    if not rule_ids:
        return jsonify({'error': 'rule_ids is required'}), 400

    from ..auth.decorators import has_permission
    cfg = _cfg()
    results = []
    errors = []

    for rule_id in rule_ids:
        rule_id = str(rule_id)
        try:
            rule_source = 'default' if int(rule_id) < 100000 else 'custom'
        except (ValueError, TypeError):
            rule_source = 'custom'

        perm = 'create_default_suppressions' if rule_source == 'default' else 'create_custom_suppressions'
        if not has_permission(session['user_id'], perm):
            errors.append({'rule_id': rule_id, 'error': 'Permission denied'})
            continue

        try:
            if rule_source == 'custom':
                existing = rule_parser.parse_rules_from_file(cfg['custom_rules_path'])
                match = next((r for r in existing if r['id'] == rule_id), None)
                if match and str(match.get('level', '')) == '0':
                    errors.append({'rule_id': rule_id, 'error': 'Already suppressed'})
                    continue
                rule_builder.suppress_custom_rule(cfg['custom_rules_path'], rule_id)
                target_file = cfg['custom_rules_path']
                action_type = 'bulk_suppress'
            else:
                rule_builder.suppress_default_rule(
                    cfg['suppressions_path'], cfg['default_rules_path'], rule_id
                )
                target_file = cfg['suppressions_path']
                action_type = 'bulk_suppress'
            results.append({'rule_id': rule_id, 'success': True})
        except ValueError as e:
            if 'ALREADY_SUPPRESSED' in str(e):
                errors.append({'rule_id': rule_id, 'error': 'Already suppressed'})
            else:
                errors.append({'rule_id': rule_id, 'error': str(e)})
        except Exception as e:
            errors.append({'rule_id': rule_id, 'error': str(e)})

    if results:
        db = get_db()
        for r in results:
            r_id = r['rule_id']
            r_src = 'default' if int(r_id) < 100000 else 'custom'
            t_file = cfg['suppressions_path'] if r_src == 'default' else cfg['custom_rules_path']
            db.execute(
                '''INSERT INTO rule_actions
                   (action_type, rule_id, rule_source, target_file, created_by, notes)
                   VALUES (?,?,?,?,?,?)''',
                ('bulk_suppress', r_id, r_src, t_file, session['user_id'], notes)
            )
        db.commit()
        log_action('BULK_SUPPRESS', 'Rules', {
            'count': len(results),
            'rule_ids': [r['rule_id'] for r in results]
        })
        try:
            send_notification('bulk_suppress', {
                'count': len(results),
                'rule_ids': ', '.join(r['rule_id'] for r in results),
                'created_by': session.get('username', ''),
                'notes': notes,
            })
        except Exception:
            pass

    return jsonify({'results': results, 'errors': errors})


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

@rules_bp.route('/api/rule/<source>/<rule_id>')
@login_required
@permission_required('view_rules')
def api_get_rule(source, rule_id):
    cfg = _cfg()
    try:
        if source == 'custom':
            rules = rule_parser.parse_rules_from_file(cfg['custom_rules_path'])
        elif source == 'default':
            # Find the rule in the default rules directory
            rule_data, _ = rule_parser.find_rule_by_id(rule_id, cfg['default_rules_path'])
            if rule_data is None:
                return jsonify({'error': 'Rule not found'}), 404
            # Overlay with exceptions file if the rule has been overwritten there
            try:
                exc_rules = rule_parser.parse_rules_from_file(cfg['default_rules_exceptions_path'])
                exc = next((r for r in exc_rules if r['id'] == str(rule_id)), None)
                if exc:
                    rule_data['raw_xml'] = exc['raw_xml']
            except Exception:
                pass
            return jsonify(rule_data)
        elif source == 'exceptions':
            rules = rule_parser.parse_rules_from_file(cfg['default_rules_exceptions_path'])
        elif source == 'suppressions':
            rules = rule_parser.parse_rules_from_file(cfg['suppressions_path'])
        else:
            return jsonify({'error': 'Invalid source'}), 400

        rule = next((r for r in rules if r['id'] == str(rule_id)), None)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404

        return jsonify(rule)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/api/next_id')
@login_required
@permission_required('create_custom_rules')
def api_next_id():
    cfg = _cfg()
    next_id = rule_builder.get_next_custom_rule_id(cfg['custom_rules_path'])
    return jsonify({'next_id': next_id})


@rules_bp.route('/api/exceptions/<rule_id>')
@login_required
def api_get_rule_exceptions(rule_id):
    """Return existing negate fields for a rule from the appropriate XML file."""
    cfg = _cfg()
    try:
        rule_source = 'default' if int(rule_id) < 100000 else 'custom'
    except (ValueError, TypeError):
        rule_source = 'custom'

    try:
        if rule_source == 'custom':
            file_path = cfg['custom_rules_path']
        else:
            file_path = cfg['default_rules_exceptions_path']

        rules = rule_parser.parse_rules_from_file(file_path)
        rule = next((r for r in rules if r['id'] == str(rule_id)), None)
        if rule is None:
            return jsonify({'negate_fields': []})

        negate_fields = []
        for f in rule.get('fields', []):
            if f['negate']:
                if f['type'] == 'pcre2':
                    _, values = rule_parser.parse_pcre2_pattern(f['value'])
                else:
                    values = [f['value']] if f['value'] else []
                negate_fields.append({
                    'field_name': f['name'],
                    'match_type': f['type'],
                    'values': values,
                    'raw_pattern': f['value'],
                })

        return jsonify({'negate_fields': negate_fields})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


_wazuh_fields_cache = None  # module-level cache — parsed once per process


@rules_bp.route('/api/fields')
@login_required
def api_wazuh_fields():
    """Return sorted unique field names from WazuhFields.json (wazuh-alerts indices only)."""
    global _wazuh_fields_cache
    if _wazuh_fields_cache is not None:
        return jsonify({'fields': _wazuh_fields_cache})

    import json as _json
    fields_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'WazuhFields', 'WazuhFields.json'
    )
    try:
        with open(fields_file, 'r', encoding='utf-8') as f:
            mapping = _json.load(f)
    except Exception as e:
        return jsonify({'error': str(e), 'fields': []}), 200

    def _flatten(props, prefix=''):
        out = []
        for k, v in props.items():
            full = (prefix + '.' + k) if prefix else k
            if 'properties' in v:
                out.extend(_flatten(v['properties'], full))
            elif v.get('type') not in ('object', 'nested', None):
                out.append(full)
        return out

    all_fields = set()
    for name, idx in mapping.items():
        if not name.startswith('wazuh-alerts'):
            continue
        props = idx.get('mappings', {}).get('properties', {})
        all_fields.update(_flatten(props))

    _wazuh_fields_cache = sorted(all_fields)
    return jsonify({'fields': _wazuh_fields_cache})


@rules_bp.route('/api/rule/<source>/<rule_id>/raw', methods=['POST'])
@login_required
@permission_required('manage_rules')
def api_update_rule_raw(source, rule_id):
    """Replace a rule's XML in the appropriate file with user-supplied raw XML."""
    from .builder import update_rule_raw_xml
    from ..audit.logger import log_action
    data = request.get_json() or {}
    new_xml = (data.get('xml') or '').strip()
    if not new_xml:
        return jsonify({'error': 'xml is required'}), 400

    cfg = current_app.config['CONFIG']['wazuh']

    if source == 'custom':
        file_path = cfg.get('custom_rules_path', '')
    elif source == 'default':
        # Can only edit in exceptions file — the original default rules are system-managed
        exc_file = cfg.get('default_rules_exceptions_path', '')
        exc_rules = rule_parser.parse_rules_from_file(exc_file)
        if not any(r['id'] == str(rule_id) for r in exc_rules):
            return jsonify({'error': 'Rule not found in exceptions file. Create an exception first before editing raw.'}), 400
        file_path = exc_file
    elif source == 'suppression':
        file_path = cfg.get('suppressions_path', '')
    else:
        return jsonify({'error': 'Unknown source'}), 400

    if not file_path:
        return jsonify({'error': 'File path not configured'}), 400

    try:
        diff = update_rule_raw_xml(file_path, rule_id, new_xml)
        log_action('EDIT_RAW_XML', 'Rules', {'rule_id': rule_id, 'source': source})
        return jsonify({'success': True, 'diff': diff})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@rules_bp.route('/api/actions')
@login_required
@permission_required('view_rules')
def api_recent_actions():
    db = get_db()
    actions = db.execute(
        '''SELECT ra.*, u.username as author FROM rule_actions ra
           LEFT JOIN users u ON u.id = ra.created_by
           ORDER BY ra.created_at DESC LIMIT 50'''
    ).fetchall()
    return jsonify([dict(a) for a in actions])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_exceptions_from_custom_rules(file_path):
    """Return list of (rule, fields with negate=yes) from custom rules."""
    result = []
    rules = rule_parser.parse_rules_from_file(file_path)
    for rule in rules:
        negate_fields = [f for f in rule.get('fields', []) if f['negate']]
        if negate_fields:
            result.append({'rule': rule, 'exception_fields': negate_fields})
    return result


def _get_suppressions_from_custom_rules(file_path):
    """Return custom rules with level=0."""
    rules = rule_parser.parse_rules_from_file(file_path)
    return [r for r in rules if r.get('level') in ('0', 0)]


def _get_rule_xml_from_file(file_path, rule_id):
    try:
        return rule_parser.get_rule_raw_xml(rule_id, file_path)
    except Exception:
        return None


def _lookup_rule_description(rule_id, rule_source, cfg):
    """Return (description, level) for a rule, or ('', '') on failure."""
    try:
        if rule_source == 'custom':
            rules = rule_parser.parse_rules_from_file(cfg['custom_rules_path'])
            r = next((x for x in rules if x['id'] == str(rule_id)), None)
        else:
            r, _ = rule_parser.find_rule_by_id(str(rule_id), cfg['default_rules_path'])
        return (r.get('description', '') if r else '', str(r.get('level', '')) if r else '')
    except Exception:
        return ('', '')

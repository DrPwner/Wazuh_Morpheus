import json
import os
import re
from datetime import datetime
from flask import (Blueprint, render_template, request, jsonify, session, abort, current_app)
from ..database import get_db, get_db_direct
from ..auth.decorators import login_required, permission_required
from ..audit.logger import log_action
from ..rules import parser as rule_parser
from ..notifications.webhook_service import is_integration_enabled, get_resolution_options, fire_webhook

alerts_bp = Blueprint('alerts', __name__)


def _webhook_extras(case, db):
    """Return extra webhook fields: customer and user_email."""
    customer = case['customer'] if 'customer' in case.keys() else ''
    user_email = ''
    try:
        row = db.execute('SELECT email FROM users WHERE username = ?',
                         (session.get('username', ''),)).fetchone()
        if row:
            user_email = row['email'] or ''
    except Exception:
        pass
    return {'customer': customer, 'user_email': user_email}


@alerts_bp.route('/')
@login_required
@permission_required('view_alerts')
def cases_list():
    db = get_db()
    status_filter = request.args.get('status', 'open')
    level_min = request.args.get('level_min', 0, type=int)
    search = request.args.get('q', '').strip()
    sort_by = request.args.get('sort_by', 'last_seen')
    sort_dir = request.args.get('sort_dir', 'desc')
    page = request.args.get('page', 1, type=int)
    per_page = 50

    _sort_cols = {
        'level':       'ac.rule_level',
        'rule_id':     'CAST(ac.rule_id AS INTEGER)',
        'description': 'ac.rule_description',
        'count':       'ac.total_count',
        'first_seen':  'ac.first_seen',
        'last_seen':   'ac.last_seen',
    }
    _sort_col = _sort_cols.get(sort_by, 'ac.last_seen')
    _sort_order = 'ASC' if sort_dir == 'asc' else 'DESC'

    query = '''
        SELECT ac.*,
               COUNT(DISTINCT COALESCE(NULLIF(ae.agent_ip,''), ae.agent_id)) as agent_count,
               u.username as assigned_username,
               (SELECT COUNT(*) FROM case_notes cn WHERE cn.case_id = ac.id) as note_count
        FROM alert_cases ac
        LEFT JOIN alert_events ae ON ae.case_id = ac.id
        LEFT JOIN users u ON u.id = ac.assigned_to
        WHERE 1=1
    '''
    params = []

    if status_filter and status_filter != 'all':
        query += ' AND ac.status = ?'
        params.append(status_filter)

    if level_min:
        query += ' AND ac.rule_level >= ?'
        params.append(level_min)

    if search:
        query += ' AND (ac.rule_id LIKE ? OR ac.rule_description LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])

    query += f' GROUP BY ac.id ORDER BY {_sort_col} {_sort_order} LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])

    cases = db.execute(query, params).fetchall()

    # Count totals
    count_query = 'SELECT COUNT(*) as cnt FROM alert_cases WHERE 1=1'
    count_params = []
    if status_filter and status_filter != 'all':
        count_query += ' AND status = ?'
        count_params.append(status_filter)

    total_count = db.execute(count_query, count_params).fetchone()['cnt']

    # Status summary
    summary = {}
    for row in db.execute(
        'SELECT status, COUNT(*) as cnt FROM alert_cases GROUP BY status'
    ).fetchall():
        summary[row['status']] = row['cnt']

    customer_field = current_app.config.get('CONFIG', {}).get('alerts', {}).get('customer_field', '')

    return render_template(
        'alerts/list.html',
        cases=cases,
        status_filter=status_filter,
        level_min=level_min,
        search=search,
        sort_by=sort_by,
        sort_dir=sort_dir,
        page=page,
        per_page=per_page,
        total_count=total_count,
        has_next=len(cases) == per_page,
        summary=summary,
        customer_field=customer_field,
        active_page='alerts'
    )


@alerts_bp.route('/<int:case_id>')
@login_required
@permission_required('view_alert_details')
def case_detail(case_id):
    db = get_db()
    case = db.execute('SELECT * FROM alert_cases WHERE id = ?', (case_id,)).fetchone()
    if not case:
        abort(404)

    # Fetch 100 events for display in the accordion
    events = db.execute(
        '''SELECT * FROM alert_events WHERE case_id = ?
           ORDER BY timestamp DESC LIMIT 100''',
        (case_id,)
    ).fetchall()

    # Parse raw_json for display
    parsed_events = []
    for ev in events:
        try:
            raw = json.loads(ev['raw_json']) if ev['raw_json'] else {}
        except Exception:
            raw = {}
        parsed_events.append({'event': dict(ev), 'parsed': raw})

    # Fetch ALL events' raw_json for accurate common_fields counts
    all_raw = db.execute(
        'SELECT raw_json FROM alert_events WHERE case_id = ?',
        (case_id,)
    ).fetchall()
    all_parsed_for_fields = []
    for row in all_raw:
        try:
            raw = json.loads(row['raw_json']) if row['raw_json'] else {}
        except Exception:
            raw = {}
        all_parsed_for_fields.append({'event': {}, 'parsed': raw})

    # Existing actions (exceptions/suppressions) for this rule
    actions = db.execute(
        '''SELECT ra.*, u.username as author FROM rule_actions ra
           LEFT JOIN users u ON u.id = ra.created_by
           WHERE ra.rule_id = ? ORDER BY ra.created_at DESC''',
        (case['rule_id'],)
    ).fetchall()

    # Extract unique fields from all events for exception builder
    silenced = set(current_app.config.get('CONFIG', {}).get('wazuh', {}).get('silenced_fields', []))
    all_fields, field_event_counts, total_events, field_value_counts = _extract_fields_from_events(all_parsed_for_fields, silenced)
    # Common fields: fields where every event has exactly one identical value
    # {field: value} — only included if all events agree on the same single value
    # Common fields only make sense with 2+ events — with 1 event every field is "common"
    common_fields = {}
    if total_events >= 2:
        for field, val_counts in field_value_counts.items():
            # field must appear in every event and have exactly one unique value
            if field_event_counts.get(field, 0) == total_events and len(val_counts) == 1:
                the_value = next(iter(val_counts.keys()))
                common_fields[field] = the_value

    # Similar fields: when 2+ events, find common substrings (4+ chars) across
    # differing values in the same field, suggesting patterns for negation
    similar_fields = {}
    if total_events >= 2:
        similar_fields = _find_similar_fields(all_fields, field_event_counts, total_events, common_fields)

    # Fetch raw XML for the rule so the detail page can show its logic.
    # For default rules, check the exceptions file first — if the rule has been
    # overwritten there, show the modified (excepted) version instead of the original.
    cfg = current_app.config.get('CONFIG', {}).get('wazuh', {})
    rule_xml = None
    try:
        rule_id_int = int(case['rule_id'])
        if rule_id_int < 100000:
            exc_rule = None
            try:
                exc_rules = rule_parser.parse_rules_from_file(cfg.get('default_rules_exceptions_path', ''))
                exc_rule = next((r for r in exc_rules if r['id'] == case['rule_id']), None)
            except Exception:
                pass
            if exc_rule:
                rule_xml = exc_rule.get('raw_xml', '')
            else:
                rule_data, _ = rule_parser.find_rule_by_id(case['rule_id'], cfg.get('default_rules_path', ''))
                if rule_data:
                    rule_xml = rule_data.get('raw_xml', '')
        else:
            rules = rule_parser.parse_rules_from_file(cfg.get('custom_rules_path', ''))
            rule_data = next((r for r in rules if r['id'] == case['rule_id']), None)
            if rule_data:
                rule_xml = rule_data.get('raw_xml', '')
    except Exception:
        rule_xml = None

    log_action('VIEW_CASE', 'Alerts', {'case_id': case_id, 'rule_id': case['rule_id']})

    event_columns = current_app.config.get('CONFIG', {}).get('alerts', {}).get(
        'event_columns',
        [{'field': 'timestamp', 'label': 'Timestamp'},
         {'field': 'agent.name', 'label': 'Endpoint'},
         {'field': 'agent.ip', 'label': 'IP Address'}]
    )

    return render_template(
        'alerts/detail.html',
        case=dict(case),
        events=parsed_events,
        actions=actions,
        all_fields=all_fields,
        common_fields=common_fields,
        similar_fields=similar_fields,
        rule_xml=rule_xml,
        event_columns=event_columns,
        active_page='alerts'
    )


def _extract_fields_from_events(parsed_events, silenced=None):
    """Build a flat dict of fieldpath -> [unique values] from parsed alert events.

    Returns a tuple (fields, field_event_counts, total_events, field_value_counts) where:
      fields             — {fieldpath: [sorted unique values]}
      field_event_counts — {fieldpath: number_of_events_containing_it}
      total_events       — len(parsed_events)
      field_value_counts — {fieldpath: {value: event_count}} per-value occurrence counts
    """
    if silenced is None:
        silenced = set()
    fields = {}
    field_event_counts = {}
    field_value_counts = {}

    def _clean_key(k):
        return re.sub(r'\s+', '', str(k))

    def _clean_val(v):
        return re.sub(r'[\r\n]+', '', str(v)) if v is not None else ''

    def _collect(obj, prefix='', result=None):
        """Recursively collect (key, val) pairs from a nested dict/list."""
        if result is None:
            result = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                clean = _clean_key(k)
                new_prefix = f'{prefix}{clean}.' if prefix else f'{clean}.'
                _collect(v, new_prefix, result)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item, prefix, result)
        else:
            key = prefix.rstrip('.')
            if key and obj is not None and key not in silenced and key != 'timestamp':
                val = _clean_val(obj)
                if val:
                    result.add((key, val))
        return result

    for item in parsed_events:
        kv_pairs = _collect(item['parsed'])
        seen_fields = set()
        for key, val in kv_pairs:
            if key not in fields:
                fields[key] = set()
            fields[key].add(val)
            seen_fields.add(key)
            # Count how many events have this exact (field, value) pair
            if key not in field_value_counts:
                field_value_counts[key] = {}
            field_value_counts[key][val] = field_value_counts[key].get(val, 0) + 1
        for f in seen_fields:
            field_event_counts[f] = field_event_counts.get(f, 0) + 1

    return (
        {k: sorted(v) for k, v in fields.items()},
        field_event_counts,
        len(parsed_events),
        field_value_counts,
    )


def _find_similar_fields(all_fields, field_event_counts, total_events, common_fields):
    """Find fields with differing values that share common substrings (4+ chars).

    Returns {field: [substring1, substring2, ...]} where substrings appear in
    multiple distinct values for the same field.
    """
    similar = {}
    MIN_LEN = 4

    for field, values in all_fields.items():
        # Skip fields that are already common (identical value)
        if field in common_fields:
            continue
        # Only look at fields present in most events
        if field_event_counts.get(field, 0) < 2:
            continue
        if len(values) < 2:
            continue
        # Limit to first 20 values for performance
        vals = values[:20]
        # Find common substrings across pairs of values
        # Split each value into tokens (by path separators, spaces, dots, etc.)
        token_sets = []
        for v in vals:
            tokens = set()
            # Split on common delimiters
            parts = re.split(r'[/\\.\s:,;=\-_\(\)\[\]]+', str(v))
            for p in parts:
                p = p.strip()
                if len(p) >= MIN_LEN:
                    tokens.add(p.lower())
            token_sets.append(tokens)

        if not token_sets:
            continue

        # Find tokens that appear in 2+ values
        token_count = {}
        for tset in token_sets:
            for t in tset:
                token_count[t] = token_count.get(t, 0) + 1

        shared = [t for t, c in token_count.items() if c >= 2]
        if shared:
            # Sort by frequency (most common first), limit to top 5
            shared.sort(key=lambda t: -token_count[t])
            similar[field] = shared[:5]

    return similar


@alerts_bp.route('/<int:case_id>/close', methods=['POST'])
@login_required
@permission_required('close_alerts')
def close_case(case_id):
    data = request.get_json() or {}
    status = data.get('status', 'ignored')
    notes = (data.get('notes') or '').strip()
    if not notes:
        return jsonify({'error': 'Notes are required'}), 400

    resolution = (data.get('resolution') or '').strip()
    if is_integration_enabled():
        if not resolution or resolution not in get_resolution_options():
            return jsonify({'error': 'Valid resolution is required'}), 400

    if status not in ('ignored', 'excepted', 'suppressed'):
        return jsonify({'error': 'Invalid status'}), 400

    db = get_db()
    case = db.execute('SELECT * FROM alert_cases WHERE id = ?', (case_id,)).fetchone()
    if not case:
        return jsonify({'error': 'Case not found'}), 404

    db.execute(
        '''UPDATE alert_cases
           SET status = ?, notes = ?, closed_at = datetime('now'), closed_by = ?
           WHERE id = ?''',
        (status, notes, session['user_id'], case_id)
    )
    db.commit()
    log_action('CLOSE_CASE', 'Alerts', {
        'case_id': case_id,
        'rule_id': case['rule_id'],
        'status': status,
        'notes': notes
    })
    if status == 'ignored':
        try:
            from ..notifications.email_service import send_notification
            send_notification('case_ignored', {
                'rule_id': case['rule_id'],
                'rule_description': case['rule_description'] or '',
                'rule_level': case['rule_level'],
                'first_seen': case['first_seen'] or '',
                'last_seen': case['last_seen'] or '',
                'total_count': case['total_count'],
                'created_by': session.get('username', ''),
                'notes': notes,
            })
        except Exception:
            pass
        if is_integration_enabled():
            _extras = _webhook_extras(case, db)
            fire_webhook('case_ignored', {
                'action': 'case_ignored',
                'rule_id': case['rule_id'],
                'rule_description': case['rule_description'] or '',
                'notes': notes,
                'resolution': resolution,
                'username': session.get('username', ''),
                'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
                'case_id': case_id,
                'customer': _extras['customer'],
                'user_email': _extras['user_email'],
            }, current_app._get_current_object())
    return jsonify({'success': True})


@alerts_bp.route('/bulk/ignore', methods=['POST'])
@login_required
@permission_required('bulk_actions')
def bulk_ignore():
    data = request.get_json() or {}
    case_ids = data.get('case_ids', [])
    notes = (data.get('notes') or '').strip()
    if not notes:
        return jsonify({'error': 'Notes are required'}), 400

    resolution = (data.get('resolution') or '').strip()
    if is_integration_enabled():
        if not resolution or resolution not in get_resolution_options():
            return jsonify({'error': 'Valid resolution is required'}), 400

    if not case_ids:
        return jsonify({'error': 'case_ids is required'}), 400

    db = get_db()
    results = []
    errors = []

    for cid in case_ids:
        case = db.execute('SELECT * FROM alert_cases WHERE id = ? AND status = ?', (cid, 'open')).fetchone()
        if not case:
            errors.append({'case_id': cid, 'error': 'Not found or not open'})
            continue
        db.execute(
            '''UPDATE alert_cases
               SET status = 'ignored', notes = ?, closed_at = datetime('now'), closed_by = ?
               WHERE id = ?''',
            (notes, session['user_id'], cid)
        )
        results.append({'case_id': cid, 'rule_id': case['rule_id']})

    db.commit()

    if results:
        log_action('BULK_IGNORE', 'Alerts', {
            'count': len(results),
            'case_ids': [r['case_id'] for r in results],
            'notes': notes
        })
        try:
            from ..notifications.email_service import send_notification
            send_notification('bulk_ignore', {
                'count': len(results),
                'case_ids': ', '.join(str(r['case_id']) for r in results),
                'rule_ids': ', '.join(r['rule_id'] for r in results),
                'created_by': session.get('username', ''),
                'notes': notes,
            })
        except Exception:
            pass
        if is_integration_enabled():
            _extras = _webhook_extras({'customer': ''}, db)
            # Collect customer values from the ignored cases
            _customers = []
            for r in results:
                _c = db.execute('SELECT customer FROM alert_cases WHERE id = ?', (r['case_id'],)).fetchone()
                if _c:
                    _customers.append(_c['customer'] or '')
            fire_webhook('bulk_ignore', {
                'action': 'bulk_ignore',
                'rule_id': ', '.join(r['rule_id'] for r in results),
                'rule_description': '',
                'notes': notes,
                'resolution': resolution,
                'username': session.get('username', ''),
                'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
                'case_ids': [r['case_id'] for r in results],
                'rule_ids': [r['rule_id'] for r in results],
                'customers': _customers,
                'user_email': _extras['user_email'],
            }, current_app._get_current_object())

    return jsonify({'results': results, 'errors': errors})


@alerts_bp.route('/bulk/suppress', methods=['POST'])
@login_required
@permission_required('bulk_actions')
def bulk_suppress():
    data = request.get_json() or {}
    case_ids = data.get('case_ids', [])
    notes = (data.get('notes') or '').strip()
    if not notes:
        return jsonify({'error': 'Notes are required'}), 400

    resolution = (data.get('resolution') or '').strip()
    if is_integration_enabled():
        if not resolution or resolution not in get_resolution_options():
            return jsonify({'error': 'Valid resolution is required'}), 400

    if not case_ids:
        return jsonify({'error': 'case_ids is required'}), 400

    db = get_db()
    results = []
    errors = []

    # Collect unique rule IDs from the selected cases
    for cid in case_ids:
        case = db.execute('SELECT * FROM alert_cases WHERE id = ? AND status = ?', (cid, 'open')).fetchone()
        if not case:
            errors.append({'case_id': cid, 'error': 'Not found or not open'})
            continue
        results.append({'case_id': cid, 'rule_id': case['rule_id']})

    if not results:
        return jsonify({'results': [], 'errors': errors})

    # Deduplicate rule IDs — suppress each rule only once
    unique_rule_ids = list(dict.fromkeys(r['rule_id'] for r in results))

    from ..rules import builder as rule_builder, parser as rp
    from ..auth.decorators import has_permission
    from ..notifications.email_service import send_notification
    cfg = current_app.config['CONFIG']['wazuh']

    suppressed_rules = []
    suppress_errors = []

    for rule_id in unique_rule_ids:
        try:
            rule_source = 'default' if int(rule_id) < 100000 else 'custom'
        except (ValueError, TypeError):
            rule_source = 'custom'

        perm = 'create_default_suppressions' if rule_source == 'default' else 'create_custom_suppressions'
        if not has_permission(session['user_id'], perm):
            suppress_errors.append({'rule_id': rule_id, 'error': 'Permission denied'})
            continue

        try:
            if rule_source == 'custom':
                existing = rp.parse_rules_from_file(cfg['custom_rules_path'])
                match = next((r for r in existing if r['id'] == rule_id), None)
                if match and str(match.get('level', '')) == '0':
                    suppress_errors.append({'rule_id': rule_id, 'error': 'Already suppressed'})
                    continue
                rule_builder.suppress_custom_rule(cfg['custom_rules_path'], rule_id)
            else:
                rule_builder.suppress_default_rule(cfg['suppressions_path'], cfg['default_rules_path'], rule_id)

            suppressed_rules.append(rule_id)
        except ValueError as e:
            if 'ALREADY_SUPPRESSED' in str(e):
                suppress_errors.append({'rule_id': rule_id, 'error': 'Already suppressed'})
            else:
                suppress_errors.append({'rule_id': rule_id, 'error': str(e)})
        except Exception as e:
            suppress_errors.append({'rule_id': rule_id, 'error': str(e)})

    # Close all cases whose rules were successfully suppressed
    closed_cases = []
    for r in results:
        if r['rule_id'] in suppressed_rules:
            db.execute(
                '''UPDATE alert_cases SET status = 'suppressed', notes = ?,
                   closed_at = datetime('now'), closed_by = ? WHERE id = ?''',
                (notes, session['user_id'], r['case_id'])
            )
            closed_cases.append(r)

    # Record suppression actions
    for rule_id in suppressed_rules:
        r_src = 'default' if int(rule_id) < 100000 else 'custom'
        t_file = cfg['suppressions_path'] if r_src == 'default' else cfg['custom_rules_path']
        db.execute(
            '''INSERT INTO rule_actions
               (action_type, rule_id, rule_source, target_file, created_by, notes)
               VALUES (?,?,?,?,?,?)''',
            ('bulk_suppress', rule_id, r_src, t_file, session['user_id'], notes)
        )

    db.commit()

    if suppressed_rules:
        log_action('BULK_SUPPRESS', 'Alerts', {
            'count': len(suppressed_rules),
            'rule_ids': suppressed_rules,
            'case_ids': [r['case_id'] for r in closed_cases],
            'notes': notes
        })
        try:
            send_notification('bulk_suppress', {
                'count': len(suppressed_rules),
                'rule_ids': ', '.join(suppressed_rules),
                'created_by': session.get('username', ''),
                'notes': notes,
            })
        except Exception:
            pass
        if is_integration_enabled():
            _extras = _webhook_extras({'customer': ''}, db)
            _customers = []
            for r in closed_cases:
                _c = db.execute('SELECT customer FROM alert_cases WHERE id = ?', (r['case_id'],)).fetchone()
                if _c:
                    _customers.append(_c['customer'] or '')
            fire_webhook('bulk_suppress', {
                'action': 'bulk_suppress',
                'rule_id': ', '.join(suppressed_rules),
                'rule_description': '',
                'notes': notes,
                'resolution': resolution,
                'username': session.get('username', ''),
                'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
                'case_ids': [r['case_id'] for r in closed_cases],
                'rule_ids': suppressed_rules,
                'customers': _customers,
                'user_email': _extras['user_email'],
            }, current_app._get_current_object())

    return jsonify({
        'results': closed_cases,
        'errors': errors + suppress_errors
    })


@alerts_bp.route('/<int:case_id>/reopen', methods=['POST'])
@login_required
@permission_required('close_alerts')
def reopen_case(case_id):
    db = get_db()
    db.execute(
        "UPDATE alert_cases SET status = 'open', closed_at = NULL, closed_by = NULL WHERE id = ?",
        (case_id,)
    )
    db.commit()
    log_action('REOPEN_CASE', 'Alerts', {'case_id': case_id})
    return jsonify({'success': True})


@alerts_bp.route('/<int:case_id>/assign', methods=['POST'])
@login_required
@permission_required('close_alerts')
def assign_case(case_id):
    data = request.get_json() or {}
    assigned_to = data.get('user_id')
    db = get_db()
    db.execute('UPDATE alert_cases SET assigned_to = ? WHERE id = ?', (assigned_to, case_id))
    db.commit()
    log_action('ASSIGN_CASE', 'Alerts', {'case_id': case_id, 'assigned_to': assigned_to})
    return jsonify({'success': True})


@alerts_bp.route('/api/cases')
@login_required
@permission_required('view_alerts')
def api_cases():
    """Return cases as JSON — used by the live-polling JS on the list page."""
    db = get_db()
    status_filter = request.args.get('status', 'open')
    search = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 50

    query = '''
        SELECT ac.*,
               COUNT(DISTINCT COALESCE(NULLIF(ae.agent_ip,''), ae.agent_id)) as agent_count,
               (SELECT COUNT(*) FROM case_notes cn WHERE cn.case_id = ac.id) as note_count
        FROM alert_cases ac
        LEFT JOIN alert_events ae ON ae.case_id = ac.id
        WHERE 1=1
    '''
    params = []
    if status_filter and status_filter != 'all':
        query += ' AND ac.status = ?'
        params.append(status_filter)
    if search:
        query += ' AND (ac.rule_id LIKE ? OR ac.rule_description LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    query += ' GROUP BY ac.id ORDER BY ac.last_seen DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])

    cases = db.execute(query, params).fetchall()

    summary = {}
    for row in db.execute(
        'SELECT status, COUNT(*) as cnt FROM alert_cases GROUP BY status'
    ).fetchall():
        summary[row['status']] = row['cnt']

    return jsonify({
        'cases': [dict(c) for c in cases],
        'summary': summary,
    })


@alerts_bp.route('/<int:case_id>/rule/raw', methods=['POST'])
@login_required
@permission_required('edit_raw_xml')
def update_case_rule_raw(case_id):
    """Edit the raw XML of the rule associated with a case."""
    from ..rules.builder import update_rule_raw_xml
    data = request.get_json() or {}
    new_xml = (data.get('xml') or '').strip()
    if not new_xml:
        return jsonify({'error': 'xml is required'}), 400

    db = get_db()
    case = db.execute('SELECT * FROM alert_cases WHERE id = ?', (case_id,)).fetchone()
    if not case:
        return jsonify({'error': 'Case not found'}), 404

    rule_id = case['rule_id']
    cfg = current_app.config['CONFIG']['wazuh']

    try:
        rule_id_int = int(rule_id)
    except ValueError:
        return jsonify({'error': 'Invalid rule ID'}), 400

    if rule_id_int < 100000:
        exc_file = cfg.get('default_rules_exceptions_path', '')
        exc_rules = rule_parser.parse_rules_from_file(exc_file)
        if not any(r['id'] == str(rule_id) for r in exc_rules):
            return jsonify({'error': 'Rule not in exceptions file. Create an exception first before editing raw.'}), 400
        file_path = exc_file
    else:
        file_path = cfg.get('custom_rules_path', '')

    if not file_path:
        return jsonify({'error': 'File path not configured'}), 400

    try:
        diff = update_rule_raw_xml(file_path, rule_id, new_xml)
        log_action('EDIT_RAW_XML', 'Alerts', {'case_id': case_id, 'rule_id': rule_id})
        return jsonify({'success': True, 'diff': diff})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@alerts_bp.route('/api/stats')
@login_required
@permission_required('view_dashboard')
def api_stats():
    db = get_db()
    summary = {}
    for row in db.execute(
        'SELECT status, COUNT(*) as cnt FROM alert_cases GROUP BY status'
    ).fetchall():
        summary[row['status']] = row['cnt']

    recent = db.execute(
        '''SELECT rule_id, rule_description, rule_level, last_seen, total_count
           FROM alert_cases WHERE status = 'open'
           ORDER BY last_seen DESC LIMIT 10'''
    ).fetchall()

    level_dist = db.execute(
        '''SELECT rule_level, COUNT(*) as cnt FROM alert_cases
           WHERE status = 'open' GROUP BY rule_level ORDER BY rule_level DESC'''
    ).fetchall()

    return jsonify({
        'summary': summary,
        'recent_open': [dict(r) for r in recent],
        'level_distribution': [dict(r) for r in level_dist],
    })


@alerts_bp.route('/api/fields/<int:case_id>')
@login_required
@permission_required('view_alert_details')
def api_case_fields(case_id):
    """Return the sorted flat field names extracted from this case's events."""
    db = get_db()
    all_raw = db.execute(
        'SELECT raw_json FROM alert_events WHERE case_id = ?', (case_id,)
    ).fetchall()
    all_parsed = []
    for row in all_raw:
        try:
            raw = json.loads(row['raw_json']) if row['raw_json'] else {}
        except Exception:
            raw = {}
        all_parsed.append({'event': {}, 'parsed': raw})
    silenced = set(current_app.config.get('CONFIG', {}).get('wazuh', {}).get('silenced_fields', []))
    fields, field_event_counts, total_events, field_value_counts = _extract_fields_from_events(all_parsed, silenced)
    # Common fields only make sense with 2+ events
    common_fields = {}
    if total_events >= 2:
        for field, val_counts in field_value_counts.items():
            if field_event_counts.get(field, 0) == total_events and len(val_counts) == 1:
                common_fields[field] = next(iter(val_counts.keys()))
    similar_fields = {}
    if total_events >= 2:
        similar_fields = _find_similar_fields(fields, field_event_counts, total_events, common_fields)
    return jsonify({'fields': sorted(fields.keys()), 'common_fields': common_fields, 'similar_fields': similar_fields})


@alerts_bp.route('/api/events/<int:case_id>')
@login_required
@permission_required('view_alert_details')
def api_events(case_id):
    db = get_db()
    page = request.args.get('page', 1, type=int)
    per_page = 25
    events = db.execute(
        'SELECT * FROM alert_events WHERE case_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?',
        (case_id, per_page, (page - 1) * per_page)
    ).fetchall()
    total = db.execute('SELECT COUNT(*) as cnt FROM alert_events WHERE case_id = ?', (case_id,)).fetchone()['cnt']
    return jsonify({
        'events': [dict(e) for e in events],
        'total': total,
        'page': page
    })


def _iter_alerts_from_file(file_path):
    """
    Yield parsed alert dicts from an alerts.json file.
    Handles all common formats:
      - JSON Lines (one object per line, standard Wazuh format)
      - JSON array  [ {...}, {...} ]
      - Pretty-printed / multi-line objects
    Uses strict=False to allow literal newlines and control characters inside
    string values (common in Wazuh full_log fields).
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    # strict=False: allow literal control chars (newlines etc.) inside strings
    decoder = json.JSONDecoder(strict=False)

    # Attempt 1: whole-file parse — handles a single JSON array or single object
    try:
        root = decoder.decode(content.strip())
        if isinstance(root, list):
            for item in root:
                if isinstance(item, dict):
                    yield item
            return
        elif isinstance(root, dict):
            yield root
            return
    except json.JSONDecodeError:
        pass

    # Attempt 2: progressive raw_decode across the full content.
    # On failure advance only 1 char so we don't skip into sub-objects.
    pos = 0
    length = len(content)
    while pos < length:
        # Skip whitespace, commas, and array brackets between objects
        while pos < length and content[pos] in ' \t\n\r,[':
            pos += 1
        if pos >= length or content[pos] == ']':
            break
        try:
            obj, end = decoder.raw_decode(content, pos)
            if isinstance(obj, dict):
                yield obj
            pos = end
        except json.JSONDecodeError:
            pos += 1


@alerts_bp.route('/api/import', methods=['POST'])
@login_required
@permission_required('view_alerts')
def import_alerts_file():
    """Manually import all events from the configured alerts.json file."""
    from .tailer import process_alert

    config = current_app.config['CONFIG']
    alerts_path = os.path.normpath(config['wazuh']['alerts_json_path'])

    if not os.path.exists(alerts_path):
        return jsonify({'error': f'Alerts file not found: {alerts_path}'}), 404

    db_path = current_app.config['DB_PATH']
    db = get_db_direct(db_path)

    inserted = 0
    skip_level0 = 0
    skip_dedup = 0
    errors = 0
    first_error = None
    first_alert_debug = None

    # Row counts before import (to verify writes land)
    rows_before = db.execute('SELECT COUNT(*) as n FROM alert_events').fetchone()['n']

    try:
        for alert in _iter_alerts_from_file(alerts_path):
            rule = alert.get('rule', {})
            rule_level = rule.get('level', 0)
            wazuh_id = alert.get('id', '') or ''

            if first_alert_debug is None:
                first_alert_debug = {
                    'top_keys': list(alert.keys()),
                    'rule_id': str(rule.get('id', 'MISSING')),
                    'rule_level': rule_level,
                    'wazuh_id': wazuh_id,
                }

            try:
                result = process_alert(alert, db)
                if result:
                    inserted += 1
                elif rule_level == 0:
                    skip_level0 += 1
                else:
                    skip_dedup += 1
            except Exception as e:
                errors += 1
                if first_error is None:
                    first_error = f'{type(e).__name__}: {e}'
                try:
                    db.rollback()
                except Exception:
                    pass

        db.commit()
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        try:
            db.close()
        except Exception:
            pass
        return jsonify({'error': str(e)}), 500

    rows_after = db.execute('SELECT COUNT(*) as n FROM alert_events').fetchone()['n']

    try:
        db.close()
    except Exception:
        pass

    skipped = skip_level0 + skip_dedup
    log_action('IMPORT_ALERTS', 'Alerts', {
        'file': alerts_path,
        'inserted': inserted,
        'skipped': skipped,
        'errors': errors,
    })
    return jsonify({
        'inserted': inserted,
        'skip_level0': skip_level0,
        'skip_dedup': skip_dedup,
        'errors': errors,
        'first_error': first_error,
        'rows_before': rows_before,
        'rows_after': rows_after,
        'first_alert': first_alert_debug,
        'db_path': db_path,
    })


# ============================================================
# Case Notes CRUD
# ============================================================

@alerts_bp.route('/<int:case_id>/notes')
@login_required
@permission_required('view_alert_details')
def get_notes(case_id):
    db = get_db()
    notes = db.execute(
        'SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at DESC',
        (case_id,)
    ).fetchall()
    return jsonify([dict(n) for n in notes])


@alerts_bp.route('/<int:case_id>/notes', methods=['POST'])
@login_required
@permission_required('add_notes')
def create_note(case_id):
    data = request.get_json() or {}
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'error': 'Content is required'}), 400

    db = get_db()
    case = db.execute('SELECT id FROM alert_cases WHERE id = ?', (case_id,)).fetchone()
    if not case:
        return jsonify({'error': 'Case not found'}), 404

    cur = db.execute(
        '''INSERT INTO case_notes (case_id, user_id, username, content)
           VALUES (?, ?, ?, ?)''',
        (case_id, session['user_id'], session.get('username', ''), content)
    )
    db.commit()
    log_action('ADD_NOTE', 'Alerts', {'case_id': case_id, 'note_id': cur.lastrowid})
    return jsonify({'success': True, 'note_id': cur.lastrowid})


@alerts_bp.route('/notes/<int:note_id>', methods=['PUT'])
@login_required
@permission_required('edit_own_notes')
def edit_note(note_id):
    data = request.get_json() or {}
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'error': 'Content is required'}), 400

    db = get_db()
    note = db.execute('SELECT * FROM case_notes WHERE id = ?', (note_id,)).fetchone()
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    if note['user_id'] != session['user_id']:
        return jsonify({'error': 'You can only edit your own notes'}), 403

    db.execute(
        "UPDATE case_notes SET content = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%S','now') WHERE id = ?",
        (content, note_id)
    )
    db.commit()
    log_action('EDIT_NOTE', 'Alerts', {'note_id': note_id, 'case_id': note['case_id']})
    return jsonify({'success': True})


@alerts_bp.route('/notes/<int:note_id>', methods=['DELETE'])
@login_required
@permission_required('delete_own_notes')
def delete_note(note_id):
    db = get_db()
    note = db.execute('SELECT * FROM case_notes WHERE id = ?', (note_id,)).fetchone()
    if not note:
        return jsonify({'error': 'Note not found'}), 404
    if note['user_id'] != session['user_id']:
        return jsonify({'error': 'You can only delete your own notes'}), 403

    db.execute('DELETE FROM case_notes WHERE id = ?', (note_id,))
    db.commit()
    log_action('DELETE_NOTE', 'Alerts', {'note_id': note_id, 'case_id': note['case_id']})
    return jsonify({'success': True})

import threading
import json
import os
import time
import logging

logger = logging.getLogger(__name__)
_tailer_running = False
_tailer_thread = None


def start_tailer(app):
    global _tailer_running, _tailer_thread
    if _tailer_thread and _tailer_thread.is_alive():
        return

    _tailer_running = True
    _tailer_thread = threading.Thread(
        target=_tailer_worker, args=(app,), daemon=True, name='alerts-tailer'
    )
    _tailer_thread.start()
    logger.info('Alerts tailer started')


def _tailer_worker(app):
    global _tailer_running
    with app.app_context():
        config = app.config['CONFIG']
        db_path = app.config['DB_PATH']

        # Wait for alerts.json to exist — re-read path each iteration so settings
        # changes (including switching from Linux to Windows paths) are picked up
        # without needing a server restart.
        while _tailer_running:
            alerts_path = os.path.normpath(config['wazuh']['alerts_json_path'])
            if os.path.exists(alerts_path):
                break
            logger.debug(f'Waiting for alerts file: {alerts_path}')
            time.sleep(10)

        if not _tailer_running:
            return

        alerts_path = os.path.normpath(config['wazuh']['alerts_json_path'])

        _last_size = 0
        try:
            with open(alerts_path, 'r', encoding='utf-8', errors='replace') as f:
                # Read from the beginning so events already in the file are imported.
                # Deduplication via wazuh_alert_id prevents duplicates on restart.
                # Buffer incomplete lines — Wazuh writes one JSON per line but the
                # line may arrive in chunks; also handles pretty-printed/array files.
                _decoder = json.JSONDecoder(strict=False)
                _buf = ''
                while _tailer_running:
                    # Detect file truncation/rotation: if the file shrinks or is
                    # replaced, reopen it from the beginning
                    try:
                        current_size = os.path.getsize(alerts_path)
                        current_pos = f.tell()
                        if current_size < current_pos:
                            logger.info('alerts.json truncated/rotated, reopening')
                            _buf = ''
                            break  # break to outer retry which will reopen
                    except OSError:
                        pass

                    chunk = f.read(4096)
                    if not chunk:
                        # Try to flush any complete object sitting in the buffer
                        _buf = _buf.strip()
                        if _buf:
                            try:
                                obj, _ = _decoder.raw_decode(_buf)
                                if isinstance(obj, dict):
                                    _process_alert(obj, db_path)
                                _buf = ''
                            except json.JSONDecodeError:
                                pass
                        time.sleep(0.3)
                        continue
                    _buf += chunk
                    # Extract all complete JSON objects from the buffer
                    pos = 0
                    while pos < len(_buf):
                        # Skip whitespace, commas, array brackets
                        while pos < len(_buf) and _buf[pos] in ' \t\n\r,[':
                            pos += 1
                        if pos >= len(_buf) or _buf[pos] == ']':
                            _buf = ''
                            break
                        try:
                            obj, end = _decoder.raw_decode(_buf, pos)
                            if isinstance(obj, dict):
                                _process_alert(obj, db_path)
                            pos = end
                        except json.JSONDecodeError:
                            # Incomplete object — keep remainder in buffer
                            _buf = _buf[pos:]
                            break
        except Exception as e:
            logger.error(f'Tailer error: {e}')

        # Retry after delay — handles both errors and file rotation
        time.sleep(5)
        if _tailer_running:
            _tailer_worker(app)


def process_alert(alert, db):
    """
    Process a single parsed alert dict and write it to the given DB connection.
    The caller is responsible for commit/rollback.
    Returns True if inserted, False if skipped (duplicate or level 0).
    """
    rule = alert.get('rule', {})
    rule_id = str(rule.get('id', 'unknown'))
    rule_desc = rule.get('description', '')
    rule_level = rule.get('level', 0)
    rule_groups = json.dumps(rule.get('groups', []))
    mitre_ids = json.dumps(rule.get('mitre', {}).get('id', []))
    timestamp = alert.get('timestamp', '')
    agent = alert.get('agent', {})
    wazuh_alert_id = alert.get('id', '') or ''

    if rule_level == 0:
        return False

    # Dedup: skip if already processed (gracefully handles missing column)
    if wazuh_alert_id:
        try:
            already = db.execute(
                'SELECT id FROM alert_events WHERE wazuh_alert_id = ?',
                (wazuh_alert_id,)
            ).fetchone()
            if already:
                return False
        except Exception:
            pass  # wazuh_alert_id column not yet migrated — skip dedup check

    existing = db.execute(
        "SELECT id FROM alert_cases WHERE rule_id = ? AND status = 'open'",
        (rule_id,)
    ).fetchone()

    if existing:
        case_id = existing['id']
        db.execute(
            "UPDATE alert_cases SET last_seen = ?, total_count = total_count + 1 WHERE id = ?",
            (timestamp, case_id)
        )
    else:
        cur = db.execute(
            '''INSERT INTO alert_cases
               (rule_id, rule_description, rule_level, rule_groups, mitre_ids,
                first_seen, last_seen, total_count, status)
               VALUES (?,?,?,?,?,?,?,1,'open')''',
            (rule_id, rule_desc, rule_level, rule_groups, mitre_ids, timestamp, timestamp)
        )
        case_id = cur.lastrowid

    event_cur = db.execute(
        '''INSERT INTO alert_events
           (case_id, timestamp, agent_id, agent_name, agent_ip, agent_labels, raw_json)
           VALUES (?,?,?,?,?,?,?)''',
        (
            case_id,
            timestamp,
            agent.get('id', ''),
            agent.get('name', ''),
            agent.get('ip', ''),
            json.dumps(agent.get('labels', {})),
            json.dumps(alert),
        )
    )
    # Store wazuh_alert_id if the column exists (migration may not have run yet)
    if wazuh_alert_id:
        try:
            db.execute(
                'UPDATE alert_events SET wazuh_alert_id = ? WHERE id = ?',
                (wazuh_alert_id, event_cur.lastrowid)
            )
        except Exception:
            pass

    return True


def _process_alert(alert, db_path):
    from ..database import get_db_direct
    db = get_db_direct(db_path)
    try:
        process_alert(alert, db)
        db.commit()
    except Exception as e:
        logger.error(f'DB error in tailer: {e}')
        db.rollback()
    finally:
        db.close()

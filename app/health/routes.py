import subprocess
import re
import shutil
import threading
import time
from collections import deque
from datetime import datetime, timezone
from flask import Blueprint, render_template, jsonify, request, session, current_app
from ..auth.decorators import login_required, permission_required
from ..audit.logger import log_action
from ..notifications.email_service import send_notification
from ..database import get_db

# 5-hour FIFO buffer for CPU usage history (one sample per poll interval)
# Each entry: {'t': ISO timestamp, 'pct': float cpu_percent}
# At 30s poll interval, 5 hours = 600 samples
_CPU_HISTORY_MAX = 600
_cpu_history = deque(maxlen=_CPU_HISTORY_MAX)

# Per-disk threshold debounce — tracks which mounts have already been alerted
_alerted_disks = set()

health_bp = Blueprint('health', __name__)


@health_bp.route('/')
@login_required
@permission_required('view_health')
def health_dashboard():
    log_action('VIEW_HEALTH', 'Health')
    cfg = current_app.config.get('CONFIG', {})
    poll_ms = int(cfg.get('health', {}).get('poll_interval_seconds', 30)) * 1000
    return render_template('health.html', active_page='health', poll_interval_ms=poll_ms)


@health_bp.route('/api/status')
@login_required
@permission_required('view_health')
def api_status():
    from .indexer_monitor import get_indexer_status
    return jsonify({
        'service': _get_service_status(),
        'disk': _get_disk_usage(),
        'network': _get_network_usage(),
        'memory': _get_memory_usage(),
        'cpu': _get_cpu_usage(),
        'indexers': get_indexer_status(),
    })


@health_bp.route('/api/service')
@login_required
@permission_required('view_health')
def api_service():
    return jsonify(_get_service_status())


@health_bp.route('/api/disk')
@login_required
@permission_required('view_health')
def api_disk():
    return jsonify(_get_disk_usage())


@health_bp.route('/api/network')
@login_required
@permission_required('view_health')
def api_network():
    return jsonify(_get_network_usage())


@health_bp.route('/api/restart', methods=['POST'])
@login_required
@permission_required('restart_wazuh')
def restart_wazuh():
    data = request.get_json() or {}
    reason = (data.get('reason') or '').strip()
    if not reason:
        return jsonify({'error': 'Reason is required'}), 400
    db = get_db()

    cur = db.execute(
        '''INSERT INTO wazuh_restarts (triggered_by, reason, status)
           VALUES (?, ?, 'pending')''',
        (session['user_id'], reason)
    )
    restart_id = cur.lastrowid
    db.commit()

    log_action('RESTART_WAZUH', 'Health', {'reason': reason, 'restart_id': restart_id})

    # Run restart in background thread
    def do_restart(app, rid, uid, uname):
        with app.app_context():
            db2 = get_db()
            try:
                result = subprocess.run(
                    ['systemctl', 'restart', 'wazuh-manager.service'],
                    capture_output=True, text=True, timeout=60
                )
                time.sleep(3)
                status_result = subprocess.run(
                    ['systemctl', 'status', 'wazuh-manager.service'],
                    capture_output=True, text=True, timeout=15
                )
                journal_result = subprocess.run(
                    ['journalctl', '-u', 'wazuh-manager.service', '-n', '20', '--no-pager'],
                    capture_output=True, text=True, timeout=15
                )

                combined = (
                    f"=== systemctl restart output ===\n"
                    f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}\n"
                    f"Return code: {result.returncode}\n\n"
                    f"=== systemctl status ===\n{status_result.stdout}\n\n"
                    f"=== journalctl (last 20 lines) ===\n{journal_result.stdout}"
                )

                success = result.returncode == 0
                db2.execute(
                    '''UPDATE wazuh_restarts SET status = ?, output = ?,
                       completed_at = datetime('now') WHERE id = ?''',
                    ('success' if success else 'failed', combined, rid)
                )
                db2.commit()

                send_notification(
                    'wazuh_restart_success' if success else 'wazuh_restart_failure',
                    {
                        'status': 'success' if success else 'failed',
                        'triggered_by': uname,
                        'reason': reason,
                        'output': combined[:2000],
                    }
                )
            except subprocess.TimeoutExpired:
                db2.execute(
                    '''UPDATE wazuh_restarts SET status = 'failed',
                       output = 'Command timed out after 60 seconds',
                       completed_at = datetime('now') WHERE id = ?''',
                    (rid,)
                )
                db2.commit()
                send_notification('wazuh_restart_failure', {
                    'status': 'timeout',
                    'triggered_by': uname,
                    'reason': reason,
                })
            except Exception as e:
                db2.execute(
                    '''UPDATE wazuh_restarts SET status = 'failed',
                       output = ?, completed_at = datetime('now') WHERE id = ?''',
                    (str(e), rid)
                )
                db2.commit()

    t = threading.Thread(
        target=do_restart,
        args=(current_app._get_current_object(), restart_id,
              session['user_id'], session['username']),
        daemon=True
    )
    t.start()

    return jsonify({'success': True, 'restart_id': restart_id, 'message': 'Restart initiated'})


@health_bp.route('/api/restart/<int:restart_id>/status')
@login_required
@permission_required('view_health')
def restart_status(restart_id):
    db = get_db()
    row = db.execute('SELECT * FROM wazuh_restarts WHERE id = ?', (restart_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(dict(row))


@health_bp.route('/api/restart/history')
@login_required
@permission_required('view_health')
def restart_history():
    db = get_db()
    rows = db.execute(
        '''SELECT wr.*, u.username FROM wazuh_restarts wr
           LEFT JOIN users u ON u.id = wr.triggered_by
           ORDER BY wr.started_at DESC LIMIT 50'''
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# System data collectors
# ---------------------------------------------------------------------------

def _get_service_status():
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'wazuh-manager.service'],
            capture_output=True, text=True, timeout=5
        )
        active = result.stdout.strip() == 'active'

        detail = subprocess.run(
            ['systemctl', 'status', 'wazuh-manager.service', '--no-pager', '-l'],
            capture_output=True, text=True, timeout=5
        )
        return {
            'active': active,
            'state': result.stdout.strip(),
            'details': detail.stdout[:3000] if detail.stdout else '',
            'error': None,
        }
    except FileNotFoundError:
        return {
            'active': False,
            'state': 'unknown',
            'details': 'systemctl not available (not running on Linux?)',
            'error': 'systemctl not found',
        }
    except Exception as e:
        return {'active': False, 'state': 'error', 'details': '', 'error': str(e)}


def _get_disk_usage():
    try:
        # Get all mount points — no filesystem-type filter, show everything df shows
        result = subprocess.run(
            ['df', '-h', '--output=source,fstype,size,used,avail,pcent,target'],
            capture_output=True, text=True, timeout=5
        )
        disks = []
        raw_lines = result.stdout.strip().split('\n')
        # df wraps long device names onto a separate line; rejoin them
        lines = []
        if len(raw_lines) > 1:
            i = 1  # skip header
            while i < len(raw_lines):
                parts = raw_lines[i].split()
                if len(parts) == 1 and i + 1 < len(raw_lines):
                    # device name on its own line, values on the next
                    lines.append(raw_lines[i] + ' ' + raw_lines[i + 1])
                    i += 2
                else:
                    lines.append(raw_lines[i])
                    i += 1
        for line in lines:
            parts = line.split()
            if len(parts) >= 7:
                try:
                    pct = int(parts[5].replace('%', ''))
                except ValueError:
                    pct = 0
                disks.append({
                    'device': parts[0],
                    'fstype': parts[1],
                    'size': parts[2],
                    'used': parts[3],
                    'available': parts[4],
                    'percent': pct,
                    'mount': ' '.join(parts[6:]),
                })

        # Check per-disk thresholds
        global _alerted_disks
        notif_cfg = {}
        try:
            from flask import current_app
            notif_cfg = current_app.config['CONFIG'].get('notifications', {})
        except Exception:
            pass

        if notif_cfg.get('on_disk_threshold', True):
            disk_thresholds = notif_cfg.get('disk_thresholds', [])
            # Build lookup: mount -> threshold for enabled entries
            thresh_map = {}
            for dt in disk_thresholds:
                if dt.get('enabled', True):
                    thresh_map[dt['mount']] = int(dt.get('threshold', 80))

            # Also use legacy global threshold as fallback when no per-disk config
            global_threshold = notif_cfg.get('disk_threshold_percent', 80)
            if not thresh_map:
                # Legacy mode: alert on all disks with global threshold
                for disk in disks:
                    mount = disk['mount']
                    if disk['percent'] >= global_threshold:
                        if mount not in _alerted_disks:
                            _alerted_disks.add(mount)
                            send_notification('disk_threshold', {
                                'mount': mount,
                                'percent': disk['percent'],
                                'threshold': global_threshold,
                            })
                    else:
                        _alerted_disks.discard(mount)
            else:
                for disk in disks:
                    mount = disk['mount']
                    if mount in thresh_map:
                        threshold = thresh_map[mount]
                        if disk['percent'] >= threshold:
                            if mount not in _alerted_disks:
                                _alerted_disks.add(mount)
                                send_notification('disk_threshold', {
                                    'mount': mount,
                                    'percent': disk['percent'],
                                    'threshold': threshold,
                                })
                        else:
                            _alerted_disks.discard(mount)

        return {'disks': disks, 'error': None}
    except Exception as e:
        return {'disks': [], 'error': str(e)}


def _get_network_usage():
    try:
        result = subprocess.run(
            ['cat', '/proc/net/dev'],
            capture_output=True, text=True, timeout=5
        )
        interfaces = []
        lines = result.stdout.strip().split('\n')
        for line in lines[2:]:
            parts = line.strip().split()
            if len(parts) >= 10:
                iface = parts[0].rstrip(':')
                if iface in ('lo',):
                    continue
                interfaces.append({
                    'interface': iface,
                    'rx_bytes': int(parts[1]),
                    'rx_packets': int(parts[2]),
                    'rx_errors': int(parts[3]),
                    'tx_bytes': int(parts[9]),
                    'tx_packets': int(parts[10]),
                    'tx_errors': int(parts[11]),
                })
        return {'interfaces': interfaces, 'error': None}
    except Exception as e:
        return {'interfaces': [], 'error': str(e)}


def _get_memory_usage():
    try:
        result = subprocess.run(
            ['free', '-m'],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split('\n')
        mem_line = lines[1].split() if len(lines) > 1 else []
        swap_line = lines[2].split() if len(lines) > 2 else []
        mem = {
            'total': int(mem_line[1]) if len(mem_line) > 1 else 0,
            'used': int(mem_line[2]) if len(mem_line) > 2 else 0,
            'free': int(mem_line[3]) if len(mem_line) > 3 else 0,
            'percent': 0,
        }
        if mem['total'] > 0:
            mem['percent'] = round(mem['used'] / mem['total'] * 100, 1)
        swap = {
            'total': int(swap_line[1]) if len(swap_line) > 1 else 0,
            'used': int(swap_line[2]) if len(swap_line) > 2 else 0,
            'free': int(swap_line[3]) if len(swap_line) > 3 else 0,
        }
        return {'memory': mem, 'swap': swap, 'error': None}
    except Exception as e:
        return {'memory': {}, 'swap': {}, 'error': str(e)}


def _get_cpu_usage():
    try:
        result = subprocess.run(
            ['top', '-bn1'],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.split('\n')
        cpu_line = next((l for l in lines if l.startswith('%Cpu') or 'Cpu(s)' in l), '')

        # Parse CPU percentage from top output
        # Format: %Cpu(s):  2.3 us,  0.7 sy, ... 96.3 id, ...
        # CPU usage = 100 - idle
        cpu_pct = 0
        idle_match = re.search(r'(\d+\.?\d*)\s*id', cpu_line)
        if idle_match:
            cpu_pct = round(100 - float(idle_match.group(1)), 1)

        load_result = subprocess.run(
            ['cat', '/proc/loadavg'],
            capture_output=True, text=True, timeout=5
        )
        load_parts = load_result.stdout.strip().split()

        # Store sample in FIFO history
        now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        _cpu_history.append({'t': now_iso, 'pct': cpu_pct})

        return {
            'cpu_percent': cpu_pct,
            'load_1': float(load_parts[0]) if load_parts else 0,
            'load_5': float(load_parts[1]) if len(load_parts) > 1 else 0,
            'load_15': float(load_parts[2]) if len(load_parts) > 2 else 0,
            'cpu_info': cpu_line.strip(),
            'history': list(_cpu_history),
            'error': None,
        }
    except Exception as e:
        return {'cpu_percent': 0, 'load_1': 0, 'load_5': 0, 'load_15': 0, 'history': list(_cpu_history), 'error': str(e)}

import threading
import os
import time
import logging

logger = logging.getLogger(__name__)
_archives_tailer_running = False
_archives_tailer_thread = None


def start_archives_tailer(app):
    global _archives_tailer_running, _archives_tailer_thread
    if _archives_tailer_thread and _archives_tailer_thread.is_alive():
        return
    _archives_tailer_running = True
    _archives_tailer_thread = threading.Thread(
        target=_archives_tailer_worker, args=(app,), daemon=True, name='archives-tailer'
    )
    _archives_tailer_thread.start()
    logger.info('Archives tailer started')


def _archives_tailer_worker(app):
    global _archives_tailer_running
    with app.app_context():
        config = app.config['CONFIG']

        # Wait until archives path is configured and the file exists.
        # Re-checks every 30 s so a path set after startup is picked up.
        while _archives_tailer_running:
            archives_path = config['wazuh'].get('archives_json_path', '').strip()
            if not archives_path:
                time.sleep(30)
                continue
            archives_path = os.path.normpath(archives_path)
            if os.path.exists(archives_path):
                break
            logger.debug('Waiting for archives file: %s', archives_path)
            time.sleep(30)

        if not _archives_tailer_running:
            return

        archives_path = os.path.normpath(config['wazuh'].get('archives_json_path', ''))
        last_log_time = time.time()
        alert_sent = False
        _last_config_check = time.time()
        _threshold = int(config['wazuh'].get('no_log_alert_seconds', 0))

        try:
            with open(archives_path, 'r', encoding='utf-8', errors='replace') as f:
                # Seek to end — we only care about new entries from this point
                f.seek(0, 2)
                while _archives_tailer_running:
                    line = f.readline()
                    if line:
                        # Any data received — reset the no-log timer
                        # (line content is intentionally discarded; we only track presence)
                        last_log_time = time.time()
                        alert_sent = False
                    else:
                        # No new data — perform config checks and gap detection once per second
                        now = time.time()
                        if now - _last_config_check >= 1.0:
                            _last_config_check = now

                            current_path = config['wazuh'].get('archives_json_path', '').strip()
                            current_path = os.path.normpath(current_path) if current_path else ''
                            if current_path != archives_path:
                                logger.info('Archives path changed — restarting tailer')
                                _archives_tailer_worker(app)
                                return

                            _threshold = int(config['wazuh'].get('no_log_alert_seconds', 0))

                        if _threshold > 0:
                            elapsed = now - last_log_time
                            if elapsed >= _threshold and not alert_sent:
                                # Suppress during quiet hours
                                try:
                                    from ..notifications.email_service import is_quiet_hours
                                    if is_quiet_hours(config):
                                        alert_sent = True
                                    else:
                                        _send_no_log_alert(elapsed, archives_path)
                                        alert_sent = True
                                except Exception:
                                    _send_no_log_alert(elapsed, archives_path)
                                    alert_sent = True
                        time.sleep(1)
        except Exception as e:
            logger.error('Archives tailer error: %s', e)
            time.sleep(10)
            if _archives_tailer_running:
                _archives_tailer_worker(app)


def _send_no_log_alert(elapsed_seconds, archives_path):
    try:
        from ..notifications.email_service import send_notification
        send_notification('archives_no_log', {
            'elapsed': int(elapsed_seconds),
            'path': archives_path,
        })
    except Exception as e:
        logger.error('Failed to send archives no-log alert: %s', e)

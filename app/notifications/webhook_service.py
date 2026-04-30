"""Webhook integration service for firing payloads to external systems (e.g. Logic Apps)."""

import json
import logging
import threading
from datetime import datetime

import requests

logger = logging.getLogger(__name__)


def is_integration_enabled(config=None):
    """Check if webhook integration is enabled (resolution dropdown + validation).

    This only checks the enabled flag — webhook_url is checked separately in
    fire_webhook() so the resolution workflow works even before a URL is configured.
    """
    if config is None:
        from flask import current_app
        config = current_app.config.get('CONFIG', {})
    return bool(config.get('integration', {}).get('enabled'))


def get_resolution_options(config=None):
    """Return the configured resolution option labels."""
    if config is None:
        from flask import current_app
        config = current_app.config.get('CONFIG', {})
    return config.get('integration', {}).get('resolution_options', [])


def fire_webhook(event_type, payload, app):
    """Fire a webhook POST in a daemon thread. Logs result to webhook_log table.

    Args:
        event_type: e.g. 'case_ignored', 'exception_created'
        payload: dict with action details
        app: Flask app instance (needed for config + DB access outside request)
    """
    config = app.config.get('CONFIG', {})
    integ = config.get('integration', {})

    if not integ.get('enabled'):
        return
    if not integ.get('webhook_events', {}).get(event_type, True):
        return

    url = (integ.get('webhook_url') or '').strip()
    if not url:
        return

    auth_type = integ.get('auth_type', 'bearer')
    auth_token = integ.get('auth_token', '')
    auth_header_name = integ.get('auth_header_name', 'Authorization')
    timeout = max(1, min(60, int(integ.get('timeout_seconds', 10))))
    retry_count = max(0, min(5, int(integ.get('retry_count', 2))))

    def _send():
        db_path = app.config['DB_PATH']
        headers = {'Content-Type': 'application/json'}
        if auth_token:
            if auth_type == 'bearer':
                headers['Authorization'] = f'Bearer {auth_token}'
            else:
                headers[auth_header_name] = auth_token

        body = json.dumps(payload)
        last_error = None
        last_status = None
        last_body = None
        success = False

        for attempt in range(1, retry_count + 2):
            try:
                resp = requests.post(url, data=body, headers=headers, timeout=timeout)
                last_status = resp.status_code
                last_body = resp.text[:2000] if resp.text else ''
                if 200 <= resp.status_code < 300:
                    success = True
                    _log_delivery(db_path, event_type, payload, last_status,
                                  last_body, True, attempt, None)
                    return
                last_error = f'HTTP {resp.status_code}'
            except requests.RequestException as e:
                last_error = str(e)[:500]

        _log_delivery(db_path, event_type, payload, last_status,
                      last_body, False, retry_count + 1, last_error)

    t = threading.Thread(target=_send, daemon=True)
    t.start()


def _log_delivery(db_path, event_type, payload, status, response_body,
                   success, attempt, error):
    """Write a row to webhook_log."""
    from ..database import get_db_direct
    try:
        db = get_db_direct(db_path)
        db.execute(
            '''INSERT INTO webhook_log
               (event_type, rule_id, rule_description, resolution,
                payload, response_status, response_body, success, attempt, error)
               VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (
                event_type,
                str(payload.get('rule_id', '')),
                payload.get('rule_description', ''),
                payload.get('resolution', ''),
                json.dumps(payload)[:4000],
                status,
                (response_body or '')[:2000],
                1 if success else 0,
                attempt,
                error,
            )
        )
        db.commit()
        db.close()
    except Exception as e:
        logger.error('Failed to log webhook delivery: %s', e)


def test_webhook(url, auth_type, auth_token, auth_header_name):
    """Send a test payload to the given URL. Returns (success, status, body)."""
    headers = {'Content-Type': 'application/json'}
    if auth_token:
        if auth_type == 'bearer':
            headers['Authorization'] = f'Bearer {auth_token}'
        else:
            headers[auth_header_name or 'Authorization'] = auth_token

    test_payload = {
        'action': 'test',
        'message': 'Wazuh Morpheus webhook test',
        'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
    }

    try:
        resp = requests.post(url, json=test_payload, headers=headers, timeout=15)
        return (200 <= resp.status_code < 300, resp.status_code, resp.text[:2000])
    except requests.RequestException as e:
        return (False, 0, str(e)[:500])

"""
Email notification service.
Reads config and sends notifications for configured events.
"""
import re
import os
import smtplib
import json
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app

logger = logging.getLogger(__name__)


def is_quiet_hours(config):
    """Return True if the current server time falls within the configured quiet hours window."""
    notif_cfg = config.get('notifications', {})
    if not notif_cfg.get('quiet_hours_enabled'):
        return False
    try:
        now = datetime.now().strftime('%H:%M')
        start = notif_cfg.get('quiet_hours_start', '00:00')
        end = notif_cfg.get('quiet_hours_end', '06:00')
        if start <= end:
            # Same-day range, e.g. 01:00–06:00
            return start <= now < end
        else:
            # Overnight range, e.g. 23:00–06:00
            return now >= start or now < end
    except Exception:
        return False

EMAILS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'emails')

EVENT_SUBJECTS = {
    'exception_created':      'Wazuh Morpheus - Exception Created for Rule {rule_id}',
    'suppression_created':    'Wazuh Morpheus - Rule {rule_id} Suppressed',
    'rule_created':           'Wazuh Morpheus - New Custom Rule Created: {rule_id}',
    'wazuh_restart_success':  'Wazuh Morpheus - Wazuh Manager Restarted Successfully',
    'wazuh_restart_failure':  'Wazuh Morpheus - Wazuh Manager Restart FAILED',
    'disk_threshold':         'Wazuh Morpheus - Disk Usage Alert: {mount} at {percent}%',
    'case_ignored':           'Wazuh Morpheus - Alert Case Ignored (Rule {rule_id})',
    'archives_no_log':        'Wazuh Morpheus - Archives Log Gap: No entries for {elapsed}s',
    'indexer_issue':           'Wazuh Morpheus - Indexer Issue: {indexer_name}',
    'bulk_ignore':             'Wazuh Morpheus - Bulk Ignore: {count} Cases',
    'bulk_suppress':           'Wazuh Morpheus - Bulk Suppress: {count} Rules',
}

NOTIFICATION_FLAGS = {
    'exception_created':      'on_exception_created',
    'suppression_created':    'on_suppression_created',
    'rule_created':           'on_rule_created',
    'wazuh_restart_success':  'on_wazuh_restart_success',
    'wazuh_restart_failure':  'on_wazuh_restart_failure',
    'disk_threshold':         'on_disk_threshold',
    'case_ignored':           'on_case_ignored',
    'archives_no_log':        'on_archives_no_log',
    'indexer_issue':           'on_indexer_issue',
    'bulk_ignore':             'on_bulk_ignore',
    'bulk_suppress':           'on_bulk_suppress',
}


def _load_template(event_type, cfg):
    """Load the HTML template for the given event type (custom or default)."""
    tpl_cfg = cfg.get('email_templates', {}).get(event_type, {})
    use_custom = tpl_cfg.get('use_custom', False)

    if use_custom:
        custom_path = os.path.join(EMAILS_DIR, 'custom_emails', f'{event_type}.html')
        if os.path.exists(custom_path):
            with open(custom_path, 'r', encoding='utf-8') as f:
                return f.read()

    default_path = os.path.join(EMAILS_DIR, f'{event_type}.html')
    if os.path.exists(default_path):
        with open(default_path, 'r', encoding='utf-8') as f:
            return f.read()

    return None


def _render_template(html_content, context):
    """
    Replace {{ variable }} or {{ variable:fallback }} placeholders.
    Values are HTML-escaped. Empty/missing values use fallback if provided.
    """
    def replacer(match):
        key = match.group(1).strip()
        fallback = match.group(2)
        val = context.get(key)
        if val is None or str(val).strip() == '':
            val = fallback.strip() if fallback is not None else ''
        elif isinstance(val, list):
            val = ', '.join(str(v) for v in val)
        else:
            val = str(val)
        return val.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return re.sub(r'\{\{\s*(\w+)\s*(?::\s*([^}]*?)\s*)?\}\}', replacer, html_content)


def send_notification(event_type, context=None):
    """
    Send an email notification for the given event_type if configured.
    Sends via SMTP and/or Postfix depending on which are enabled.
    context: dict of template variables.
    """
    context = context or {}
    context.setdefault('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    try:
        cfg = current_app.config['CONFIG']
        email_cfg = cfg.get('email', {})
        postfix_cfg = cfg.get('postfix', {})
        notif_cfg = cfg.get('notifications', {})

        smtp_enabled = email_cfg.get('enabled', False)
        postfix_enabled = postfix_cfg.get('enabled', False)
        if not smtp_enabled and not postfix_enabled:
            return

        flag = NOTIFICATION_FLAGS.get(event_type)
        if flag and not notif_cfg.get(flag, True):
            return

        def _parse_recipients(value):
            """Split a comma-separated address string into a clean list."""
            if isinstance(value, list):
                return [a.strip() for a in value if str(a).strip()]
            return [a.strip() for a in str(value or '').split(',') if a.strip()]

        # Recipients are configured per-event in notifications.event_recipients
        # Config keys use on_ prefix (e.g. on_exception_created) matching the toggle keys
        event_recipients_cfg = notif_cfg.get('event_recipients', {})
        flag_key = NOTIFICATION_FLAGS.get(event_type, event_type)
        event_addr = event_recipients_cfg.get(flag_key) or event_recipients_cfg.get(event_type) or ''
        recipients = _parse_recipients(event_addr)
        if not recipients:
            return

        subject_tpl = EVENT_SUBJECTS.get(event_type, f'Wazuh Morpheus - {event_type}')
        try:
            subject = subject_tpl.format(**context)
        except KeyError:
            subject = subject_tpl

        body_text = _build_body(event_type, context)

        html_body = None
        tpl = _load_template(event_type, cfg)
        if tpl:
            html_body = _render_template(tpl, context)

        _save_notification(event_type, subject, body_text, recipients)

        # Send via SMTP if enabled
        if smtp_enabled and email_cfg.get('smtp_host'):
            try:
                send_email_direct(
                    smtp_host=email_cfg['smtp_host'],
                    smtp_port=int(email_cfg.get('smtp_port', 587)),
                    smtp_user=email_cfg.get('smtp_user', ''),
                    smtp_password=email_cfg.get('smtp_password', ''),
                    smtp_tls=bool(email_cfg.get('smtp_tls', True)),
                    from_address=email_cfg.get('from_address', email_cfg.get('smtp_user', '')),
                    to_addresses=recipients,
                    subject=subject,
                    body=body_text,
                    html_body=html_body,
                )
            except Exception as e:
                logger.error(f'SMTP notification failed for {event_type}: {e}')

        # Send via Postfix if enabled
        if postfix_enabled and postfix_cfg.get('host'):
            try:
                send_email_postfix(
                    host=postfix_cfg.get('host', 'localhost'),
                    port=int(postfix_cfg.get('port', 25)),
                    from_address=postfix_cfg.get('from_address', ''),
                    use_tls=bool(postfix_cfg.get('use_tls', False)),
                    to_addresses=recipients,
                    subject=subject,
                    body=body_text,
                    html_body=html_body,
                    username=postfix_cfg.get('username', ''),
                    password=postfix_cfg.get('password', ''),
                )
            except Exception as e:
                logger.error(f'Postfix notification failed for {event_type}: {e}')
    except Exception as e:
        logger.error(f'Notification failed for {event_type}: {e}')


def send_email_direct(smtp_host, smtp_port, smtp_user, smtp_password,
                       smtp_tls, from_address, to_addresses, subject, body,
                       html_body=None):
    """Send an email directly with the given parameters."""
    if not to_addresses:
        raise ValueError('No recipients specified')

    msg = MIMEMultipart('alternative')
    msg['From'] = from_address
    msg['To'] = ', '.join(to_addresses)
    msg['Subject'] = subject

    text_part = MIMEText(body, 'plain', 'utf-8')
    actual_html = html_body if html_body else _text_to_html(body)
    html_part = MIMEText(actual_html, 'html', 'utf-8')
    msg.attach(text_part)
    msg.attach(html_part)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        if smtp_tls:
            smtp.starttls()
        if smtp_user and smtp_password:
            smtp.login(smtp_user, smtp_password)
        smtp.sendmail(from_address, to_addresses, msg.as_string())

    logger.info(f'Email sent: {subject} -> {to_addresses}')


def send_email_postfix(host, port, from_address, use_tls, to_addresses,
                       subject, body, html_body=None,
                       username='', password=''):
    """Send an email via a Postfix/MTA relay (optional authentication)."""
    if not to_addresses:
        raise ValueError('No recipients specified')

    msg = MIMEMultipart('alternative')
    msg['From'] = from_address
    msg['To'] = ', '.join(to_addresses)
    msg['Subject'] = subject

    text_part = MIMEText(body, 'plain', 'utf-8')
    actual_html = html_body if html_body else _text_to_html(body)
    html_part = MIMEText(actual_html, 'html', 'utf-8')
    msg.attach(text_part)
    msg.attach(html_part)

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if use_tls:
            smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.sendmail(from_address, to_addresses, msg.as_string())

    logger.info(f'Postfix email sent: {subject} -> {to_addresses}')


def _build_body(event_type, context):
    lines = [f'Wazuh Morpheus Notification', f'Event: {event_type}', '']
    for key, val in context.items():
        lines.append(f'{key.replace("_", " ").title()}: {val}')
    lines.append('')
    lines.append('---')
    lines.append('This is an automated notification from the Wazuh Morpheus.')
    return '\n'.join(lines)


def _text_to_html(text):
    html_body = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br>')
    return f'''<!DOCTYPE html>
<html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
<div style="background: #1d63a0; color: white; padding: 12px 20px; border-radius: 4px 4px 0 0;">
  <h2 style="margin:0">Wazuh Morpheus</h2>
</div>
<div style="border: 1px solid #ddd; border-top: none; padding: 20px; border-radius: 0 0 4px 4px;">
  {html_body}
</div>
</body></html>'''


def _save_notification(event_type, subject, body, recipients):
    """Persist notification record to DB."""
    try:
        db = current_app.extensions.get('db') or _get_db_fallback()
        if db:
            db.execute(
                '''INSERT INTO notification_events (event_type, subject, message, recipients, sent, sent_at)
                   VALUES (?, ?, ?, ?, 1, datetime('now'))''',
                (event_type, subject, body[:500], json.dumps(recipients))
            )
            db.commit()
    except Exception:
        pass


def _get_db_fallback():
    try:
        from flask import g
        from ..database import get_db
        return get_db()
    except Exception:
        return None

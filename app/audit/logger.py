import json
from flask import session, request, current_app, g
from ..database import get_db


def log_action(action, category=None, details=None, user_id=None, username=None):
    """
    Write an entry to the audit log.

    Can be called from:
    - Request context: user_id/username from session if not provided
    - Background threads: pass user_id/username explicitly
    """
    try:
        uid = user_id or session.get('user_id')
        uname = username or session.get('username')
        ip = None
        try:
            ip = request.remote_addr
        except RuntimeError:
            pass

        details_str = None
        if details is not None:
            if isinstance(details, (dict, list)):
                details_str = json.dumps(details)
            else:
                details_str = str(details)

        try:
            db = get_db()
        except RuntimeError:
            # Outside request context — use direct connection
            from ..database import get_db_direct
            db_path = current_app.config['DB_PATH'] if current_app else None
            if not db_path:
                return
            db = get_db_direct(db_path)
            db.execute(
                '''INSERT INTO audit_log (user_id, username, action, category, details, ip_address)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (uid, uname, action, category, details_str, ip)
            )
            db.commit()
            db.close()
            return

        db.execute(
            '''INSERT INTO audit_log (user_id, username, action, category, details, ip_address)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (uid, uname, action, category, details_str, ip)
        )
        db.commit()
    except Exception as e:
        # Audit log failures must never break normal flow
        try:
            current_app.logger.error(f'Audit log failed: {e}')
        except Exception:
            pass

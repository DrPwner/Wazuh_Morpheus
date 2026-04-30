from functools import wraps
from flask import session, redirect, url_for, abort, request, jsonify
from ..database import get_db


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated


def permission_required(permission_name):
    """Decorator: requires user to have the named permission."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('auth.login', next=request.url))
            if not has_permission(session['user_id'], permission_name):
                if request.is_json:
                    return jsonify({'error': 'Permission denied'}), 403
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator


def has_permission(user_id, permission_name):
    """Return True if user_id has the named permission."""
    db = get_db()

    # Root users have all permissions
    user = db.execute('SELECT is_root FROM users WHERE id = ? AND is_active = 1', (user_id,)).fetchone()
    if not user:
        return False
    if user['is_root']:
        return True

    # Explicit user-level grant (takes priority over roles)
    user_perm = db.execute('''
        SELECT granted FROM user_permissions up
        JOIN permissions p ON up.permission_id = p.id
        WHERE up.user_id = ? AND p.name = ?
    ''', (user_id, permission_name)).fetchone()

    if user_perm is not None:
        return bool(user_perm['granted'])

    # Role-level grant
    role_perm = db.execute('''
        SELECT COUNT(*) AS cnt FROM role_permissions rp
        JOIN permissions p ON rp.permission_id = p.id
        JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = ? AND p.name = ?
    ''', (user_id, permission_name)).fetchone()

    return role_perm['cnt'] > 0


def get_user_permissions(user_id):
    """Return set of permission names the user has."""
    db = get_db()
    user = db.execute('SELECT is_root FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return set()
    if user['is_root']:
        perms = db.execute('SELECT name FROM permissions').fetchall()
        return {r['name'] for r in perms}

    perms = set()

    # Role permissions
    role_perms = db.execute('''
        SELECT DISTINCT p.name FROM permissions p
        JOIN role_permissions rp ON rp.permission_id = p.id
        JOIN user_roles ur ON ur.role_id = rp.role_id
        WHERE ur.user_id = ?
    ''', (user_id,)).fetchall()
    perms.update(r['name'] for r in role_perms)

    # Explicit user overrides
    user_perms = db.execute('''
        SELECT p.name, up.granted FROM user_permissions up
        JOIN permissions p ON up.permission_id = p.id
        WHERE up.user_id = ?
    ''', (user_id,)).fetchall()
    for row in user_perms:
        if row['granted']:
            perms.add(row['name'])
        else:
            perms.discard(row['name'])

    return perms

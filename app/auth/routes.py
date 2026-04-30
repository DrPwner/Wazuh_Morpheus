import json
from flask import (Blueprint, render_template, request, session, redirect,
                   url_for, flash, jsonify, abort, current_app)
from werkzeug.security import generate_password_hash, check_password_hash
from ..database import get_db, PERMISSIONS
from ..audit.logger import log_action
from .decorators import login_required, permission_required, has_permission, get_user_permissions

auth_bp = Blueprint('auth', __name__)


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('alerts.cases_list'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ? AND is_active = 1', (username,)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_root'] = bool(user['is_root'])
            session['permissions'] = list(get_user_permissions(user['id']))

            db.execute(
                "UPDATE users SET last_login = datetime('now'), last_ip = ? WHERE id = ?",
                (request.remote_addr, user['id'])
            )
            db.commit()
            log_action('LOGIN', 'Auth', {'ip': request.remote_addr},
                       user_id=user['id'], username=user['username'])

            next_url = request.args.get('next')
            return redirect(next_url or url_for('alerts.cases_list'))
        else:
            error = 'Invalid username or password.'
            log_action('LOGIN_FAILED', 'Auth', {'username': username, 'ip': request.remote_addr})

    return render_template('auth/login.html', error=error)


@auth_bp.route('/logout')
@login_required
def logout():
    log_action('LOGOUT', 'Auth')
    session.clear()
    return redirect(url_for('auth.login'))


# ---------------------------------------------------------------------------
# User management (admin / manage_users permission)
# ---------------------------------------------------------------------------

@auth_bp.route('/users')
@login_required
@permission_required('manage_users')
def users_list():
    db = get_db()
    users = db.execute(
        '''SELECT u.id, u.username, u.email, u.full_name, u.is_active, u.is_root,
                  u.created_at, u.last_login, u.last_ip
           FROM users u ORDER BY u.username'''
    ).fetchall()

    role_rows = db.execute(
        '''SELECT ur.user_id, r.id as role_id, r.name as role_name
           FROM user_roles ur JOIN roles r ON r.id = ur.role_id'''
    ).fetchall()
    user_roles = {}
    for rr in role_rows:
        if rr['user_id'] not in user_roles:
            user_roles[rr['user_id']] = {'id': rr['role_id'], 'name': rr['role_name']}

    all_roles = db.execute('SELECT id, name FROM roles ORDER BY name').fetchall()

    return render_template('settings/users.html', users=users,
                           user_roles=user_roles, all_roles=all_roles,
                           active_page='settings', active_sub='users')


@auth_bp.route('/users/create', methods=['POST'])
@login_required
@permission_required('manage_users')
def create_user():
    data = request.get_json() or request.form
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    email = (data.get('email') or '').strip()
    full_name = (data.get('full_name') or '').strip()
    is_root = int(bool(data.get('is_root', False)))

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        return jsonify({'error': 'Username already exists'}), 409

    ph = generate_password_hash(password)
    db.execute(
        'INSERT INTO users (username, password_hash, email, full_name, is_root) VALUES (?,?,?,?,?)',
        (username, ph, email, full_name, is_root)
    )
    db.commit()
    new_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    log_action('CREATE_USER', 'UserManagement', {'username': username, 'is_root': is_root})
    return jsonify({'success': True, 'user_id': new_user['id']})


@auth_bp.route('/users/<int:user_id>', methods=['GET'])
@login_required
@permission_required('manage_users')
def get_user(user_id):
    db = get_db()
    user = db.execute(
        'SELECT id, username, email, full_name, is_active, is_root FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    roles = db.execute(
        '''SELECT r.id, r.name FROM roles r
           JOIN user_roles ur ON ur.role_id = r.id
           WHERE ur.user_id = ?''', (user_id,)
    ).fetchall()

    user_perms = db.execute(
        '''SELECT p.name, up.granted FROM user_permissions up
           JOIN permissions p ON up.permission_id = p.id
           WHERE up.user_id = ?''', (user_id,)
    ).fetchall()

    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'full_name': user['full_name'],
        'is_active': bool(user['is_active']),
        'is_root': bool(user['is_root']),
        'roles': [{'id': r['id'], 'name': r['name']} for r in roles],
        'permissions': [{'name': p['name'], 'granted': bool(p['granted'])} for p in user_perms],
    })


@auth_bp.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
@permission_required('manage_users')
def update_user(user_id):
    # Prevent deactivating own account
    if user_id == session['user_id'] and 'is_active' in (request.get_json() or request.form):
        data = request.get_json() or request.form
        if not int(bool(data.get('is_active', 1))):
            return jsonify({'error': 'You cannot deactivate your own account'}), 400

    data = request.get_json() or request.form
    db = get_db()

    fields = []
    params = []
    if 'email' in data:
        fields.append('email = ?')
        params.append(data['email'])
    if 'full_name' in data:
        fields.append('full_name = ?')
        params.append(data['full_name'])
    if 'is_active' in data:
        fields.append('is_active = ?')
        params.append(int(bool(data['is_active'])))
    if 'password' in data and data['password']:
        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        fields.append('password_hash = ?')
        params.append(generate_password_hash(data['password']))

    if fields:
        params.append(user_id)
        db.execute(f'UPDATE users SET {", ".join(fields)} WHERE id = ?', params)
        db.commit()

    log_action('UPDATE_USER', 'UserManagement', {'user_id': user_id, 'fields': list(data.keys())})
    return jsonify({'success': True})


@auth_bp.route('/users/<int:user_id>/roles', methods=['POST'])
@login_required
@permission_required('manage_roles')
def update_user_roles(user_id):
    data = request.get_json()
    role_ids = data.get('role_ids', [])
    db = get_db()
    db.execute('DELETE FROM user_roles WHERE user_id = ?', (user_id,))
    for rid in role_ids:
        db.execute('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?,?)',
                   (user_id, rid))
    db.commit()

    # Refresh session permissions if updating self
    if user_id == session['user_id']:
        session['permissions'] = list(get_user_permissions(user_id))

    log_action('UPDATE_USER_ROLES', 'UserManagement', {'user_id': user_id, 'roles': role_ids})
    return jsonify({'success': True})


@auth_bp.route('/users/<int:user_id>/permissions', methods=['POST'])
@login_required
@permission_required('manage_roles')
def update_user_permissions(user_id):
    """
    Expects JSON: { "permissions": {"perm_name": true/false, ...} }
    True = explicitly grant, False = explicitly revoke, absent = use role
    """
    data = request.get_json()
    perms = data.get('permissions', {})
    db = get_db()

    db.execute('DELETE FROM user_permissions WHERE user_id = ?', (user_id,))
    for pname, granted in perms.items():
        perm = db.execute('SELECT id FROM permissions WHERE name = ?', (pname,)).fetchone()
        if perm:
            db.execute(
                'INSERT INTO user_permissions (user_id, permission_id, granted) VALUES (?,?,?)',
                (user_id, perm['id'], 1 if granted else 0)
            )
    db.commit()

    if user_id == session['user_id']:
        session['permissions'] = list(get_user_permissions(user_id))

    log_action('UPDATE_USER_PERMISSIONS', 'UserManagement', {'user_id': user_id})
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# Role management
# ---------------------------------------------------------------------------

@auth_bp.route('/roles')
@login_required
@permission_required('manage_roles')
def roles_list():
    db = get_db()
    roles = db.execute('SELECT * FROM roles ORDER BY name').fetchall()
    all_perms = db.execute('SELECT * FROM permissions ORDER BY category, name').fetchall()
    return render_template('settings/roles.html', roles=roles, all_permissions=all_perms,
                           active_page='settings', active_sub='roles')


@auth_bp.route('/roles/create', methods=['POST'])
@login_required
@permission_required('manage_roles')
def create_role():
    data = request.get_json() or request.form
    name = (data.get('name') or '').strip()
    description = (data.get('description') or '').strip()
    if not name:
        return jsonify({'error': 'Role name is required'}), 400
    db = get_db()
    db.execute('INSERT OR IGNORE INTO roles (name, description) VALUES (?,?)', (name, description))
    db.commit()
    role = db.execute('SELECT id FROM roles WHERE name = ?', (name,)).fetchone()
    log_action('CREATE_ROLE', 'UserManagement', {'name': name})
    return jsonify({'success': True, 'role_id': role['id']})


@auth_bp.route('/roles/<int:role_id>/permissions', methods=['POST'])
@login_required
@permission_required('manage_roles')
def update_role_permissions(role_id):
    data = request.get_json()
    perm_names = data.get('permissions', [])
    db = get_db()
    db.execute('DELETE FROM role_permissions WHERE role_id = ?', (role_id,))
    for pname in perm_names:
        perm = db.execute('SELECT id FROM permissions WHERE name = ?', (pname,)).fetchone()
        if perm:
            db.execute(
                'INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?,?)',
                (role_id, perm['id'])
            )
    db.commit()
    log_action('UPDATE_ROLE_PERMISSIONS', 'UserManagement', {'role_id': role_id, 'permissions': perm_names})
    return jsonify({'success': True})


@auth_bp.route('/roles/<int:role_id>', methods=['GET'])
@login_required
@permission_required('manage_roles')
def get_role(role_id):
    db = get_db()
    role = db.execute('SELECT * FROM roles WHERE id = ?', (role_id,)).fetchone()
    if not role:
        return jsonify({'error': 'Not found'}), 404
    perms = db.execute(
        '''SELECT p.name FROM role_permissions rp
           JOIN permissions p ON p.id = rp.permission_id
           WHERE rp.role_id = ?''', (role_id,)
    ).fetchall()
    return jsonify({
        'id': role['id'],
        'name': role['name'],
        'description': role['description'],
        'permissions': [p['name'] for p in perms],
    })


@auth_bp.route('/roles/<int:role_id>', methods=['DELETE'])
@login_required
@permission_required('manage_roles')
def delete_role(role_id):
    db = get_db()
    db.execute('DELETE FROM roles WHERE id = ?', (role_id,))
    db.commit()
    log_action('DELETE_ROLE', 'UserManagement', {'role_id': role_id})
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# API: current user info
# ---------------------------------------------------------------------------

@auth_bp.route('/me')
@login_required
def me():
    return jsonify({
        'user_id': session['user_id'],
        'username': session['username'],
        'is_root': session.get('is_root', False),
        'permissions': session.get('permissions', []),
    })


@auth_bp.route('/permissions')
@login_required
@permission_required('manage_roles')
def list_permissions():
    db = get_db()
    perms = db.execute('SELECT * FROM permissions ORDER BY category, name').fetchall()
    return jsonify([dict(p) for p in perms])

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db
from app.models import User
from app.forms import LoginForm
from app.auth.ldap_auth import authenticate_ldap

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login — LDAP primary, local admin fallback."""
    if current_user.is_authenticated:
        return redirect(url_for('servers.list_servers'))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        # Try LDAP first
        ldap_result = None
        if current_app.config.get('LDAP_SERVER'):
            ldap_result = authenticate_ldap(username, password, current_app)

        if ldap_result and ldap_result['authenticated']:
            user = _get_or_create_user(
                username=ldap_result['user_info']['username'],
                display_name=ldap_result['user_info'].get('display_name'),
                role=ldap_result['role'],
                is_local=False,
            )
            login_user(user)
            flash(f'Добро пожаловать, {user.display_name or user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('servers.list_servers'))

        # Fallback: local admin
        local_admin_user = User.query.filter_by(
            username=current_app.config.get('LOCAL_ADMIN_USERNAME', 'admin'),
            is_local=True
        ).first()

        if local_admin_user and local_admin_user.check_password(password):
            if not local_admin_user.is_active:
                flash('Учётная запись отключена.', 'error')
                return render_template('auth/login.html', form=form)
            login_user(local_admin_user)
            flash(f'Вход выполнен как {local_admin_user.username} (local admin)', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('servers.list_servers'))

        flash('Неверный логин или пароль.', 'error')

    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout and redirect to login page."""
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('auth.login'))


def _get_or_create_user(username, display_name=None, role='pass-user', is_local=False):
    """Get existing user or create new one from LDAP data."""
    user = User.query.filter_by(username=username).first()
    if user:
        # Update info from LDAP
        if display_name:
            user.display_name = display_name
        user.role = role
        user.is_active = True
        db.session.commit()
    else:
        user = User(
            username=username,
            display_name=display_name,
            role=role,
            is_local=is_local,
        )
        db.session.add(user)
        db.session.commit()
    return user


@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login."""
    return db.session.get(User, int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to login page."""
    return redirect(url_for('auth.login'))

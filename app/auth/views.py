from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db, login_manager
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

        # Try LDAP first (if configured)
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

        # Fallback: any local user (admin, manually seeded users)
        local_user = User.query.filter_by(username=username, is_local=True).first()
        if local_user and local_user.check_password(password):
            if not local_user.is_active:
                flash('Учётная запись отключена.', 'error')
                return render_template('auth/login.html', form=form)
            login_user(local_user)
            flash(f'Вход выполнен как {local_user.username} (local, role={local_user.role})', 'success')
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

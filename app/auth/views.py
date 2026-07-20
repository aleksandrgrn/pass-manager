import logging
import time
from collections import defaultdict

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db, login_manager
from app.models import User
from app.forms import LoginForm
from app.auth.ldap_auth import authenticate_ldap

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

# ---------------------------------------------------------------------------
# In-memory rate-limit на endpoint /login.
#
# ВАЖНО: это in-memory хранилище работает ТОЛЬКО для single-server деплоя
# (gunicorn с одним воркером или несколько воркеров без shared-memory —
# в последнем случае у каждого воркера свой словарь и лимит считается отдельно,
# что делает защиту слабее, но не ломает функциональность).
# Для multi-server / multi-worker нужна shared Redis-подобная реализация.
# Текущий деплой (b000860) — single-server, этого достаточно.
# ---------------------------------------------------------------------------
_LOGIN_MAX_ATTEMPTS = 5        # максимум попыток в окне
_LOGIN_WINDOW_SECONDS = 60     # окно подсчёта попыток
_LOGIN_BAN_SECONDS = 300       # длительность бана после превышения

# ip -> список timestamp-ов неудачных попыток
_login_attempts: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(ip: str) -> bool:
    """Проверить, разрешён ли запрос на login с данного IP.

    Правила:
      - максимум `_LOGIN_MAX_ATTEMPTS` попыток за `_LOGIN_WINDOW_SECONDS` секунд;
      - при превышении — бан на `_LOGIN_BAN_SECONDS` секунд.

    Возвращает True, если запрос разрешён; False, если IP забанен.
    Проводит очистку устаревших записей при каждом вызове.
    """
    now = time.monotonic()
    attempts = _login_attempts[ip]

    # Чистим попытки старше окна + бана: они больше не влияют на лимит
    cutoff = now - (_LOGIN_WINDOW_SECONDS + _LOGIN_BAN_SECONDS)
    _login_attempts[ip] = [t for t in attempts if t >= cutoff]
    attempts = _login_attempts[ip]

    # Сколько попыток в текущем окне
    recent = [t for t in attempts if t >= now - _LOGIN_WINDOW_SECONDS]

    if len(recent) >= _LOGIN_MAX_ATTEMPTS:
        # Когда истекает бан: последняя попытка + длительность бана
        ban_ends_at = recent[-1] + _LOGIN_BAN_SECONDS
        if now < ban_ends_at:
            return False
        # Бан истёк — сбрасываем окно и разрешаем попытку
        _login_attempts[ip] = []

    return True


def _record_failed_attempt(ip: str) -> None:
    """Зафиксировать неудачную попытку входа с данного IP."""
    _login_attempts[ip].append(time.monotonic())


def _reset_attempts(ip: str) -> None:
    """Сбросить историю попыток для IP (после успешного входа)."""
    _login_attempts.pop(ip, None)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login — LDAP primary, local admin fallback."""
    if current_user.is_authenticated:
        return redirect(url_for('servers.list_servers'))

    # Rate-limit: защищаемся от brute-force с одного IP
    client_ip = request.remote_addr or 'unknown'
    if not _check_rate_limit(client_ip):
        logger.warning('Login заблокирован rate-limit-ом для IP %s', client_ip)
        flash('Слишком много попыток входа. Попробуйте позже.', 'error')
        return render_template('auth/login.html', form=LoginForm()), 429

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
            _reset_attempts(client_ip)
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
            _reset_attempts(client_ip)
            flash(f'Вход выполнен как {local_user.username} (local, role={local_user.role})', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('servers.list_servers'))

        # Неудачная попытка — фиксируем для rate-limit
        _record_failed_attempt(client_ip)
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

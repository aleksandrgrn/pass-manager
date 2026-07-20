"""Pytest fixtures for the pass-manager test suite.

Конфигурация:
- in-memory SQLite (каждый тест видит свежую БД);
- CSRF отключён для удобства POST-запросов (тестируется отдельно в test_security);
- LDAP-сервер пустой → auth fallback на локальных пользователей;
- ENCRYPTION_KEY пустой → Fernet-обёртка работает в dev no-op режиме
  (шифрование прозрачно пропускается, гибридные свойства читаются как plaintext).
- In-memory rate-limit на login сбрасывается между тестами через автouse-фикстуру.
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest
from flask import Flask
from flask.testing import FlaskClient

from app import create_app
from app.extensions import db as _db

if TYPE_CHECKING:
    from app.models import Server, User


# --------------------------------------------------------------------------- #
# App / DB
# --------------------------------------------------------------------------- #

@pytest.fixture()
def app() -> Flask:
    """Свежий Flask-приложение с тестовой in-memory SQLite."""
    app = create_app('development')
    # Тестовые переопределения
    app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
        WTF_CSRF_ENABLED=False,
        LDAP_SERVER='',            # отключаем LDAP → всегда local fallback
        ENCRYPTION_KEY='',         # dev no-op: гибридные свойства хранят plaintext
        SECRET_KEY='test-secret-key-not-for-production',
        SERVER_NAME=None,
    )
    # In-memory rate-limit у каждого процесса свой; сбрасываем перед app start.
    _reset_login_rate_limit()

    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app: Flask):
    """db-объект с уже созданными таблицами (готов к использованию в тестах)."""
    return _db


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Тестовый клиент приложения (анонимный)."""
    return app.test_client()


# --------------------------------------------------------------------------- #
# Users (локальные, с разными ролями)
# --------------------------------------------------------------------------- #

def _make_user(db, username: str, role: str, password: str = 'pass123'):
    """Создать и сохранить локального пользователя с указанной ролью."""
    from app.models import User
    user = User(
        username=username,
        display_name=f'Test {role}',
        role=role,
        is_local=True,
        is_active=True,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def admin_user(db):
    """Пользователь с ролью pass-admin (видит пароли)."""
    return _make_user(db, username='admin_test', role='pass-admin')


@pytest.fixture()
def lead_user(db):
    """Пользователь с ролью pass-lead (видит пароли)."""
    return _make_user(db, username='lead_test', role='pass-lead')


@pytest.fixture()
def regular_user(db):
    """Пользователь с ролью pass-user (без доступа к паролям)."""
    return _make_user(db, username='user_test', role='pass-user')


# --------------------------------------------------------------------------- #
# Logged-in clients under each role
# --------------------------------------------------------------------------- #

def login_as(client: FlaskClient, username: str, password: str = 'pass123') -> None:
    """Войти под указанным логином/паролем через POST /auth/login.

    Используется и в тестах, и внутри фикстур *_client.
    """
    # Каждый вызов использует уникальный IP, чтобы не налетать в rate-limit.
    ip = f'10.{uuid.uuid4().int % 256}.{uuid.uuid4().int % 256}.{uuid.uuid4().int % 256}'
    resp = client.post(
        '/auth/login',
        data={'username': username, 'password': password},
        environ_base={'REMOTE_ADDR': ip},
    )
    assert resp.status_code == 302, (
        f'login_as({username}) ожидал 302, получил {resp.status_code}: '
        f'{resp.get_data(as_text=True)[:300]}'
    )


@pytest.fixture()
def admin_client(app: Flask, admin_user) -> FlaskClient:
    """Клиент, залогиненный под pass-admin."""
    c = app.test_client()
    login_as(c, 'admin_test')
    return c


@pytest.fixture()
def lead_client(app: Flask, lead_user) -> FlaskClient:
    """Клиент, залогиненный под pass-lead."""
    c = app.test_client()
    login_as(c, 'lead_test')
    return c


@pytest.fixture()
def regular_client(app: Flask, regular_user) -> FlaskClient:
    """Клиент, залогиненный под pass-user."""
    c = app.test_client()
    login_as(c, 'user_test')
    return c


# --------------------------------------------------------------------------- #
# Sample data
# --------------------------------------------------------------------------- #

@pytest.fixture()
def sample_server(db):
    """Сервер с паролями и двумя доменами для тестов RBAC и HTMX."""
    from app.models import Server, Domain
    server = Server(
        name='vps-test-01',
        ip_address='192.0.2.10',
        provider='TestProvider',
        provider_login='root',
        os='Ubuntu 22.04',
        active=True,
        has_exim=True,
        has_squid=False,
        has_vpn=False,
    )
    # Используем setter (работает и с plaintext, и с зашифрованной моделью).
    server.password = 's3cret-root-pass'
    server.provider_password = 'prov-pass-123'
    db.session.add(server)
    db.session.commit()

    d1 = Domain(domain='example.com', server_id=server.id)
    d2 = Domain(domain='test.example.org', server_id=server.id)
    db.session.add_all([d1, d2])
    db.session.commit()
    db.session.refresh(server)
    return server


# --------------------------------------------------------------------------- #
# Helpers / autouse
# --------------------------------------------------------------------------- #

def _reset_login_rate_limit() -> None:
    """Сбросить in-memory хранилище rate-limit между тестами."""
    try:
        from app.auth.views import _login_attempts
        _login_attempts.clear()
    except Exception:
        # Если модуль не импортируется (например, builder ещё меняет его),
        # не валим всю фикстуру — тест, где это важно, упадёт отдельно.
        pass


@pytest.fixture(autouse=True)
def _reset_rate_limit_between_tests():
    """Autouse: очищать rate-limit до И после каждого теста."""
    _reset_login_rate_limit()
    yield
    _reset_login_rate_limit()

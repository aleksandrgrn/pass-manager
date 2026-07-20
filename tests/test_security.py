"""Тесты безопасности: гибридные свойства паролей, Fernet no-op, rate-limit, CSRF."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Server


# --------------------------------------------------------------------------- #
# Гибридные свойства Server.password
# --------------------------------------------------------------------------- #

class TestHybridPasswordProperty:
    """Гибридное свойство password возвращает plaintext, не ciphertext."""

    def test_password_getter_returns_string(self, db, app):
        with app.app_context():
            s = Server(name='srv')
            s.password = 'mysecret'
            db.session.add(s)
            db.session.commit()

            # Гибридный getter должен вернуть ту же строку
            assert isinstance(s.password, str)
            assert s.password == 'mysecret'

    @pytest.mark.parametrize('field,value', [
        ('password', 'root-pw'),
        ('provider_password', 'prov-pw'),
        ('web_pass', 'web-pw'),
        ('mgt_pass', 'mgt-pw'),
    ])
    def test_each_secret_field_roundtrip(self, app, db, field, value):
        with app.app_context():
            s = Server(name='srv')
            setattr(s, field, value)
            db.session.add(s)
            db.session.commit()
            assert getattr(s, field) == value

    def test_password_none_when_unset(self, app, db):
        with app.app_context():
            s = Server(name='srv')
            db.session.add(s); db.session.commit()
            assert s.password is None


# --------------------------------------------------------------------------- #
# Dev no-op encryption (без ENCRYPTION_KEY)
# --------------------------------------------------------------------------- #

class TestDevNoOpEncryption:
    """В dev без ENCRYPTION_KEY шифрование работает как no-op (plaintext)."""

    def test_encrypt_returns_plaintext_in_dev_noop(self, app):
        from app.security import encrypt, decrypt, is_no_op_mode
        with app.app_context():
            assert is_no_op_mode() is True
            assert encrypt('hello') == 'hello'
            assert decrypt('hello') == 'hello'
            assert encrypt(None) is None
            assert encrypt('') == ''

    def test_model_saves_in_noop_mode(self, app, db):
        with app.app_context():
            s = Server(name='srv')
            s.password = 'plain'
            db.session.add(s); db.session.commit()
            # В no-op режиме encrypted-колонка содержит plaintext
            assert s.password_encrypted == 'plain'
            # Гибридное свойство тоже возвращает plaintext
            assert s.password == 'plain'


# --------------------------------------------------------------------------- #
# Реальное Fernet-шифрование (с валидным ENCRYPTION_KEY)
# --------------------------------------------------------------------------- #

class TestRealFernetEncryption:
    """С реальным ENCRYPTION_KEY пароли должны храниться как Fernet-токены."""

    def test_password_stored_as_fernet_token(self, tmp_path):
        from cryptography.fernet import Fernet
        from app import create_app

        key = Fernet.generate_key().decode()
        app = create_app('development')
        app.config.update(
            SQLALCHEMY_DATABASE_URI=f'sqlite:///{tmp_path}/fernet.db',
            WTF_CSRF_ENABLED=False,
            ENCRYPTION_KEY=key,
        )
        with app.app_context():
            db.create_all()
            s = Server(name='srv')
            s.password = 'real-secret-42'
            db.session.add(s); db.session.commit()

            # В колонке — Fernet-токен
            assert s.password_encrypted.startswith('gAAAAA')
            assert s.password_encrypted != 'real-secret-42'
            # Геттер возвращает plaintext
            assert s.password == 'real-secret-42'
            db.drop_all()


# --------------------------------------------------------------------------- #
# In-memory rate-limit на login
# --------------------------------------------------------------------------- #

class TestLoginRateLimit:
    """In-memory rate-limit на /auth/login (5 попыток / 60s, бан 300s)."""

    def test_sixth_attempt_returns_429(self, app, client):
        """6-я неудачная попытка с одного IP → 429."""
        ip = '203.0.113.77'
        statuses = []
        for _ in range(6):
            resp = client.post(
                '/auth/login',
                data={'username': 'no-such-user', 'password': 'bad'},
                environ_base={'REMOTE_ADDR': ip},
            )
            statuses.append(resp.status_code)
        # Первые 5 — 200 (форма с ошибкой), 6-я — 429
        assert statuses[:5] == [200, 200, 200, 200, 200]
        assert statuses[5] == 429

    def test_successful_login_resets_counter(self, app, db, client):
        """После успешного входа счётчик неудач для IP должен сброситься."""
        from app.models import User
        with app.app_context():
            u = User(username='rl_user', role='pass-user', is_local=True)
            u.set_password('good')
            db.session.add(u); db.session.commit()

        ip = '203.0.113.88'
        # 4 неудачные попытки (подходим к лимиту)
        for _ in range(4):
            client.post(
                '/auth/login',
                data={'username': 'rl_user', 'password': 'bad'},
                environ_base={'REMOTE_ADDR': ip},
            )
        # Успешный вход — должен сбросить счётчик
        ok = client.post(
            '/auth/login',
            data={'username': 'rl_user', 'password': 'good'},
            environ_base={'REMOTE_ADDR': ip},
        )
        assert ok.status_code == 302
        # Выходим, чтобы снова оказаться на странице login
        client.get('/auth/logout')

        # Теперь снова можно сделать 5 неудачных — не должно быть 429 на 5-й
        for i in range(5):
            r = client.post(
                '/auth/login',
                data={'username': 'rl_user', 'password': 'bad'},
                environ_base={'REMOTE_ADDR': ip},
                follow_redirects=False,
            )
            # 200 = форма с ошибкой (что и ожидаем); 302 тоже допустим,
            # если в ходе теста юзер вдруг остался залогинен.
            assert r.status_code in (200, 302), (
                f'После сброса первые 5 неудач должны быть 200/302, '
                f'попытка {i + 1} дала {r.status_code}'
            )
        # 6-я попытка точно должна быть 429 — лимит исчерпан
        r6 = client.post(
            '/auth/login',
            data={'username': 'rl_user', 'password': 'bad'},
            environ_base={'REMOTE_ADDR': ip},
        )
        assert r6.status_code == 429

    def test_different_ips_independent(self, app, client):
        """Лимит считается отдельно для каждого IP."""
        for i in range(5):
            client.post(
                '/auth/login',
                data={'username': 'x', 'password': 'y'},
                environ_base={'REMOTE_ADDR': '10.0.0.1'},
            )
        # С другого IP — лимит не задет, должно быть 200
        resp = client.post(
            '/auth/login',
            data={'username': 'x', 'password': 'y'},
            environ_base={'REMOTE_ADDR': '10.0.0.2'},
        )
        assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# CSRF protection
# --------------------------------------------------------------------------- #

class TestCSRFProtection:
    """CSRF: POST без токена → 400, если CSRF включён."""

    def test_post_without_csrf_token_returns_400(self, app, admin_user):
        """С включённым CSRF — POST /servers/new без токена → 400."""
        app.config['WTF_CSRF_ENABLED'] = True
        client = app.test_client()
        # Логин через session (минуя форму) — чтобы не требовался CSRF на /login
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
            sess['_fresh'] = True

        resp = client.post('/servers/new', data={'name': 'csrf-test'})
        assert resp.status_code == 400

    def test_post_with_valid_csrf_token_accepted(self, app, admin_user):
        """С корректным CSRF-токеном POST принимается (302 — сервер создан)."""
        app.config['WTF_CSRF_ENABLED'] = True
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin_user.id)
            sess['_fresh'] = True

        # Достаём csrf-токен из формы /servers/new (он валиден для текущей сессии)
        import re
        page = client.get('/servers/new')
        match = re.search(
            r'name="csrf_token"[^>]*value="([^"]+)"',
            page.get_data(as_text=True),
        )
        assert match, 'CSRF-токен должен присутствовать в форме /servers/new'
        token = match.group(1)

        resp = client.post(
            '/servers/new',
            data={'name': 'csrf-ok-server', 'csrf_token': token},
        )
        # С корректным токеном форма принимается → 302 (создан и редирект)
        assert resp.status_code == 302

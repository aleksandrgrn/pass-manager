"""Тесты авторизации: login/logout, корневой редирект, защита роутов."""
from __future__ import annotations

import pytest


class TestLoginGet:
    """GET /auth/login."""

    def test_login_get_returns_200(self, client):
        """Страница входа доступна анониму."""
        resp = client.get('/auth/login')
        assert resp.status_code == 200
        assert 'Войти' in resp.get_data(as_text=True)


class TestLoginPost:
    """POST /auth/login."""

    def test_correct_password_redirects(self, app, client, admin_user):
        """Верные креды → 302 на /servers/."""
        resp = client.post(
            '/auth/login',
            data={'username': 'admin_test', 'password': 'pass123'},
            environ_base={'REMOTE_ADDR': '198.51.100.10'},
        )
        assert resp.status_code == 302
        assert resp.headers['Location'].endswith('/servers/')

    def test_wrong_password_shows_form(self, client, admin_user):
        """Неверный пароль → 200 (форма с ошибкой, не редирект)."""
        resp = client.post(
            '/auth/login',
            data={'username': 'admin_test', 'password': 'WRONG'},
            environ_base={'REMOTE_ADDR': '198.51.100.11'},
        )
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        # Должна быть flash-ошибка и форма должна перерисоваться.
        assert 'Неверный логин или пароль' in body

    def test_unknown_user_shows_form(self, client):
        """Несуществующий пользователь → 200, не 500."""
        resp = client.post(
            '/auth/login',
            data={'username': 'ghost', 'password': 'whatever'},
            environ_base={'REMOTE_ADDR': '198.51.100.12'},
        )
        assert resp.status_code == 200
        assert 'Неверный логин или пароль' in resp.get_data(as_text=True)

    def test_login_redirects_when_already_authenticated(self, admin_client):
        """Повторный login уже аутентифицированного юзера → редирект."""
        resp = admin_client.get('/auth/login', follow_redirects=False)
        assert resp.status_code == 302


class TestLogout:
    """GET /auth/logout."""

    def test_logout_requires_login(self, client):
        """Logout без auth → редирект на login (через @login_required)."""
        resp = client.get('/auth/logout', follow_redirects=False)
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']

    def test_logout_redirects_to_login(self, admin_client):
        """После logout → редирект на /auth/login."""
        resp = admin_client.get('/auth/logout', follow_redirects=False)
        assert resp.status_code == 302
        assert '/auth/login' in resp.headers['Location']


class TestRootRedirect:
    """Роут '/'."""

    def test_root_anonymous_redirects_to_login(self, client):
        """Аноним → / → редирект на /auth/login (через @login_required)."""
        resp = client.get('/', follow_redirects=False)
        # / -> /servers/ -> (нет auth) -> /auth/login
        assert resp.status_code in (302, 303)
        # Из-за login_required может быть один или два шага; проверим финальный.
        final = client.get('/', follow_redirects=True)
        assert final.status_code == 200
        assert 'Войти' in final.get_data(as_text=True)

    def test_root_authenticated_redirects_to_servers(self, admin_client):
        """Залогиненный пользователь → / → /servers/."""
        resp = admin_client.get('/', follow_redirects=False)
        assert resp.status_code in (302, 303)
        assert '/servers/' in resp.headers['Location']


@pytest.mark.parametrize('route', [
    '/servers/',
    '/servers/new',
    '/servers/1',
    '/servers/1/edit',
])
def test_protected_routes_redirect_anonymous(client, route):
    """Все серверные роуты недоступны анониму → редирект на /auth/login."""
    resp = client.get(route, follow_redirects=False)
    assert resp.status_code == 302
    assert '/auth/login' in resp.headers['Location']

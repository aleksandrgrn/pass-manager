"""Тесты авторизации: login/logout, корневой редирект, защита роутов."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.auth.ldap_auth import LdapUnavailable


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

    def test_wrong_password_redirects_back(self, client, admin_user):
        """Неверный пароль → 302 назад на форму (PRG), а не отрисовка на POST.

        Рендер прямо в ответ на POST делает F5 повтором отправки учётных
        данных: браузер спрашивает «повторить?», и каждое согласие уходит в AD
        отдельным bind'ом — при пороге блокировки 6 это запирает учётку.
        """
        resp = client.post(
            '/auth/login',
            data={'username': 'admin_test', 'password': 'WRONG'},
            environ_base={'REMOTE_ADDR': '198.51.100.11'},
        )
        assert resp.status_code == 302
        assert resp.headers['Location'].endswith('/auth/login')

    def test_wrong_password_shows_error_after_redirect(self, client, admin_user):
        """Сообщение об ошибке переживает редирект (flash)."""
        resp = client.post(
            '/auth/login',
            data={'username': 'admin_test', 'password': 'WRONG'},
            environ_base={'REMOTE_ADDR': '198.51.100.13'},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert 'Неверный логин или пароль' in resp.get_data(as_text=True)

    def test_unknown_user_redirects_back(self, client):
        """Несуществующий пользователь → 302, не 500."""
        resp = client.post(
            '/auth/login',
            data={'username': 'ghost', 'password': 'whatever'},
            environ_base={'REMOTE_ADDR': '198.51.100.12'},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert 'Неверный логин или пароль' in resp.get_data(as_text=True)

    def test_broken_ldap_still_lets_local_admin_in(self, app, client, admin_user):
        """Домен лёг — локальный суперадмин всё равно входит.

        Это единственный путь внутрь, когда каталог недоступен, и нужен он
        ровно в этот момент. Поэтому поломка LDAP не прерывает вход, а лишь
        меняет сообщение при неудаче.
        """
        app.config['LDAP_SERVER'] = 'dc01.example.local'

        with patch('app.auth.views.authenticate_ldap',
                   side_effect=LdapUnavailable('служебная учётка не пустила')):
            resp = client.post(
                '/auth/login',
                data={'username': 'admin_test', 'password': 'pass123'},
                environ_base={'REMOTE_ADDR': '198.51.100.14'},
            )

        assert resp.status_code == 302
        assert resp.headers['Location'].endswith('/servers/')

    def test_broken_ldap_says_service_unavailable(self, app, client, admin_user):
        """Домен лёг, локальный пароль не подошёл → честная причина.

        «Неверный логин или пароль» здесь врёт: после ротации пароля служебной
        учётки его увидит весь отдел и пойдёт перебирать свои пароли.
        """
        app.config['LDAP_SERVER'] = 'dc01.example.local'

        with patch('app.auth.views.authenticate_ldap',
                   side_effect=LdapUnavailable('служебная учётка не пустила')):
            resp = client.post(
                '/auth/login',
                data={'username': 'mbelyakov', 'password': 'whatever'},
                environ_base={'REMOTE_ADDR': '198.51.100.15'},
                follow_redirects=True,
            )

        text = resp.get_data(as_text=True)
        assert 'Служба аутентификации недоступна' in text
        assert 'Неверный логин или пароль' not in text

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

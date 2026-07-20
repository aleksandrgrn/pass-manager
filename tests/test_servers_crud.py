"""Тесты CRUD серверов + пагинация."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Server


# --------------------------------------------------------------------------- #
# List
# --------------------------------------------------------------------------- #

class TestListServers:
    """GET /servers/."""

    def test_list_empty_shows_placeholder(self, admin_client):
        """Пустой список → сообщение 'Нет записей'."""
        resp = admin_client.get('/servers/')
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'Нет записей' in body

    def test_list_shows_server_name(self, admin_client, sample_server):
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert sample_server.name in body


# --------------------------------------------------------------------------- #
# Create
# --------------------------------------------------------------------------- #

class TestCreateServer:
    """POST /servers/new."""

    def test_create_redirects_and_persists(self, admin_client):
        resp = admin_client.post(
            '/servers/new',
            data={
                'name': 'new-server-1',
                'ip_address': '198.51.100.50',
                'provider': 'Hetzner',
                'active': 'y',
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        # В БД действительно создан сервер
        created = Server.query.filter_by(name='new-server-1').first()
        assert created is not None
        assert created.ip_address == '198.51.100.50'

    def test_create_without_name_shows_validation_error(self, admin_client):
        """POST без name → форма перерисовывается (200), в БД ничего не добавлено."""
        before = Server.query.count()
        resp = admin_client.post(
            '/servers/new',
            data={'name': '', 'ip_address': '1.1.1.1'},
        )
        assert resp.status_code == 200
        assert 'Название обязательно' in resp.get_data(as_text=True)
        assert Server.query.count() == before

    def test_create_stores_password_via_hybrid_setter(self, admin_client):
        """Если в форме указать пароль — он сохраняется через гибридное свойство."""
        admin_client.post(
            '/servers/new',
            data={'name': 'pw-server', 'password': 'abc-secret'},
        )
        srv = Server.query.filter_by(name='pw-server').first()
        assert srv is not None
        # Гибридное свойство должно вернуть именно plaintext-значение
        assert srv.password == 'abc-secret'


# --------------------------------------------------------------------------- #
# Detail
# --------------------------------------------------------------------------- #

class TestDetailServer:
    """GET /servers/<id>."""

    def test_detail_returns_200_with_name(self, admin_client, sample_server):
        resp = admin_client.get(f'/servers/{sample_server.id}')
        assert resp.status_code == 200
        assert sample_server.name in resp.get_data(as_text=True)

    def test_detail_unknown_id_returns_404(self, admin_client):
        resp = admin_client.get('/servers/99999')
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Edit (full form)
# --------------------------------------------------------------------------- #

class TestEditServer:
    """POST /servers/<id>/edit."""

    def test_edit_updates_data(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/edit',
            data={
                'name': 'renamed-via-edit',
                'ip_address': '203.0.113.99',
                'active': 'y',
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        refreshed = db.session.get(Server, sample_server.id)
        assert refreshed.name == 'renamed-via-edit'
        assert refreshed.ip_address == '203.0.113.99'


# --------------------------------------------------------------------------- #
# Delete
# --------------------------------------------------------------------------- #

class TestDeleteServer:
    """POST /servers/<id>/delete."""

    def test_delete_htmx_returns_204(self, admin_client, sample_server):
        """HTMX-запрос на удаление → 204, сервер удалён из БД."""
        sid = sample_server.id
        resp = admin_client.post(
            f'/servers/{sid}/delete',
            headers={'HX-Request': 'true'},
        )
        assert resp.status_code == 204
        assert db.session.get(Server, sid) is None

    def test_delete_non_htmx_redirects(self, admin_client, sample_server):
        """Обычный POST без HX-Request → 302 на /servers/."""
        sid = sample_server.id
        resp = admin_client.post(f'/servers/{sid}/delete', follow_redirects=False)
        assert resp.status_code == 302
        assert '/servers/' in resp.headers['Location']
        assert db.session.get(Server, sid) is None


# --------------------------------------------------------------------------- #
# Pagination
# --------------------------------------------------------------------------- #

class TestPagination:
    """Пагинация на больших списках."""

    @pytest.mark.parametrize('per_page,total,expected_pages', [
        (50, 60, 2),
        (50, 100, 2),
        (50, 50, 1),
        (50, 51, 2),
    ])
    def test_pagination_calculates_pages(
        self, app, admin_user, admin_client, per_page, total, expected_pages,
    ):
        """Проверяем, что pagination.pages считается правильно при N серверах."""
        # Создаём `total` серверов
        servers = [Server(name=f'srv-{i:03d}', ip_address=f'10.0.{i // 256}.{i % 256}')
                   for i in range(total)]
        db.session.add_all(servers)
        db.session.commit()

        # В request-context используем ITEMS_PER_PAGE из конфига
        with app.test_request_context('/servers/'):
            pagination = Server.query.paginate(
                page=1, per_page=per_page, error_out=False,
            )
            assert pagination.pages == expected_pages

    def test_60_servers_produce_two_pages_in_html(self, app, admin_client):
        """Реальный эндпоинт /servers/ при 60 серверах показывает 2 страницы."""
        app.config['ITEMS_PER_PAGE'] = 50
        db.session.add_all([
            Server(name=f'srv-{i:03d}') for i in range(60)
        ])
        db.session.commit()

        # Страница 1
        page1 = admin_client.get('/servers/?page=1')
        assert page1.status_code == 200
        body = page1.get_data(as_text=True)
        # Должна быть пагинация с двумя ссылками
        assert 'page=2' in body
        assert 'page=1' in body

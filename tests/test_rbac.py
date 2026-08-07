"""Тесты RBAC: видимость столбцов и значений паролей по ролям."""
from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# Видимость столбца "Пароль" в /servers/
# --------------------------------------------------------------------------- #

class TestPasswordColumnVisibility:
    """Столбец 'Пароль' должен присутствовать только для superadmin."""

    def test_admin_does_not_see_password_column(self, admin_client, sample_server):
        """admin не должен видеть столбец 'Пароль' в шапке таблицы."""
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert '<th>Пароль</th>' not in body

    def test_superadmin_sees_password_column(self, superadmin_client, sample_server):
        """superadmin видит столбец 'Пароль'."""
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert '<th>Пароль</th>' in body


# --------------------------------------------------------------------------- #
# Видимость значения пароля в HTML
# --------------------------------------------------------------------------- #

class TestPasswordValueVisibility:
    """Значение пароля сервера должно присутствовать в HTML только для superadmin."""

    def test_admin_does_not_see_password_value(self, admin_client, sample_server):
        """admin не должен видеть сам пароль в HTML списка."""
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert 's3cret-root-pass' not in body

    def test_superadmin_sees_password_value(self, superadmin_client, sample_server):
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert 's3cret-root-pass' in body


# --------------------------------------------------------------------------- #
# Детальная страница
# --------------------------------------------------------------------------- #

class TestDetailPage:
    """GET /servers/<id> — видимость пароля по ролям."""

    def test_admin_detail_has_no_password(self, admin_client, sample_server):
        resp = admin_client.get(f'/servers/{sample_server.id}')
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 's3cret-root-pass' not in body
        # Должна быть индикация скрытия паролей
        assert 'Пароли скрыты' in body

    def test_superadmin_detail_has_password(self, superadmin_client, sample_server):
        body = superadmin_client.get(f'/servers/{sample_server.id}').get_data(as_text=True)
        assert 's3cret-root-pass' in body


# --------------------------------------------------------------------------- #
# inline edit endpoint — RBAC enforcement (FIX-6b: metadata vs password split)
# --------------------------------------------------------------------------- #

class TestEditFieldSplit:
    """FIX-6b: metadata доступна admin+, password-поля — только superadmin."""

    def test_admin_can_edit_metadata_field(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'name', 'value': 'renamed-by-admin'},
        )
        assert resp.status_code == 200

    def test_admin_cannot_edit_password_field(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'HACKED'},
        )
        assert resp.status_code == 403

    def test_superadmin_can_edit_password_field(self, superadmin_client, sample_server):
        resp = superadmin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'new-pass-456'},
        )
        assert resp.status_code == 200


class TestInlineEditRbac:
    """POST /servers/<id>/field — admin: metadata OK / password 403; superadmin: всё OK."""

    def test_admin_cannot_edit_password_field(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'HACKED'},
        )
        assert resp.status_code == 403

    @pytest.mark.parametrize('field,value', [
        ('name', 'renamed-by-admin'),
        ('ip_address', '203.0.113.10'),
        ('notes', 'changed'),
    ])
    def test_admin_can_edit_non_password_fields(
        self, admin_client, sample_server, field, value,
    ):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': field, 'value': value},
        )
        assert resp.status_code == 200

    def test_superadmin_can_edit_password_field(self, superadmin_client, sample_server):
        """superadmin может редактировать пароль → 200 и значение меняется в БД."""
        from app.models import Server
        resp = superadmin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'new-pass-456'},
        )
        assert resp.status_code == 200
        # Проверяем, что значение реально записано (через гибридное свойство).
        from app.extensions import db
        with db.session.no_autoflush:
            refreshed = db.session.get(Server, sample_server.id)
            assert refreshed.password == 'new-pass-456'


# --------------------------------------------------------------------------- #
# Mutating endpoints: обе роли (admin + superadmin) могут мутировать серверы
# --------------------------------------------------------------------------- #

class TestRbacOnMutatingEndpoints:
    """После A1: admin и superadmin могут все mutating-действия над серверами."""

    def test_anon_cannot_create_server(self, client):
        resp = client.post('/servers/new', data={
            'name': 'evil', 'ip_address': '203.0.113.99',
        })
        assert resp.status_code in (302, 401)

    def test_anon_cannot_edit_server(self, client, sample_server):
        resp = client.post(f'/servers/{sample_server.id}/edit', data={
            'name': 'hacked', 'ip_address': sample_server.ip_address,
        })
        assert resp.status_code in (302, 401)

    def test_anon_cannot_delete_server(self, client, sample_server):
        resp = client.post(f'/servers/{sample_server.id}/delete')
        assert resp.status_code in (302, 401)

    def test_anon_cannot_toggle_field(self, client, sample_server):
        resp = client.post(
            f'/servers/{sample_server.id}/toggle',
            data={'field': 'active'},
        )
        assert resp.status_code in (302, 401)

    def test_anon_cannot_add_domain(self, client, sample_server):
        resp = client.post(
            f'/servers/{sample_server.id}/domains',
            data={'domain': 'evil.com'},
        )
        assert resp.status_code in (302, 401)

    def test_anon_cannot_delete_domain(self, client, sample_server):
        from app.models import Domain
        domain = Domain.query.filter_by(server_id=sample_server.id).first()
        resp = client.post(f'/servers/domains/{domain.id}/delete')
        assert resp.status_code in (302, 401)

    def test_admin_can_create_server(self, admin_client):
        resp = admin_client.post('/servers/new', data={
            'name': 'new-prod-01', 'ip_address': '192.0.2.50',
        })
        assert resp.status_code == 302

    def test_admin_can_edit_server(self, admin_client, sample_server):
        resp = admin_client.post(f'/servers/{sample_server.id}/edit', data={
            'name': sample_server.name, 'ip_address': '203.0.113.20',
        })
        assert resp.status_code == 302

    def test_admin_can_delete_server(self, admin_client, sample_server):
        resp = admin_client.post(f'/servers/{sample_server.id}/delete')
        assert resp.status_code == 302

    def test_admin_can_toggle_active(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/toggle',
            data={'field': 'active'},
        )
        assert resp.status_code == 200

    def test_admin_can_add_domain(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/domains',
            data={'domain': 'newdomain.com'},
        )
        assert resp.status_code == 200

    def test_admin_can_delete_domain(self, admin_client, sample_server):
        from app.models import Domain
        domain = Domain.query.filter_by(server_id=sample_server.id).first()
        resp = admin_client.post(f'/servers/domains/{domain.id}/delete')
        assert resp.status_code == 204

    def test_superadmin_can_create_server(self, superadmin_client):
        resp = superadmin_client.post('/servers/new', data={
            'name': 'new-prod-02', 'ip_address': '192.0.2.51',
        })
        assert resp.status_code == 302

    def test_superadmin_can_delete_server(self, superadmin_client, sample_server):
        resp = superadmin_client.post(f'/servers/{sample_server.id}/delete')
        assert resp.status_code == 302


# --------------------------------------------------------------------------- #
# Role properties на модели User
# --------------------------------------------------------------------------- #

class TestRoleProperties:
    """User(role=...) → is_admin / is_superadmin / can_view_passwords."""

    def test_admin_role_properties(self, app):
        from app.models import User
        u = User(username='x', role='admin')
        assert u.is_admin is True
        assert u.is_superadmin is False
        assert u.can_view_passwords is False

    def test_superadmin_role_properties(self, app):
        from app.models import User
        u = User(username='y', role='superadmin')
        assert u.is_admin is True
        assert u.is_superadmin is True
        assert u.can_view_passwords is True


# --------------------------------------------------------------------------- #
# Форма редактирования — та же граница, что у списка и карточки
# --------------------------------------------------------------------------- #

class TestEditFormPasswords:
    """GET/POST /servers/<id>/edit: пароли — только суперадмину."""

    def test_admin_edit_form_has_no_passwords(self, admin_client, sample_server):
        body = admin_client.get(
            f'/servers/{sample_server.id}/edit'
        ).get_data(as_text=True)
        assert 's3cret-root-pass' not in body
        assert 'prov-pass-123' not in body

    def test_superadmin_edit_form_has_passwords(self, superadmin_client, sample_server):
        body = superadmin_client.get(
            f'/servers/{sample_server.id}/edit'
        ).get_data(as_text=True)
        assert 's3cret-root-pass' in body

    def test_admin_edit_post_cannot_change_password(
        self, admin_client, sample_server, db,
    ):
        resp = admin_client.post(f'/servers/{sample_server.id}/edit', data={
            'name': 'vps-test-01', 'password': 'HACKED',
            'provider_password': 'HACKED-2',
        })
        assert resp.status_code == 302
        db.session.refresh(sample_server)
        assert sample_server.password == 's3cret-root-pass'
        assert sample_server.provider_password == 'prov-pass-123'

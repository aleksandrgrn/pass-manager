"""Тесты RBAC: видимость столбцов и значений паролей по ролям."""
from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# Видимость столбца "Пароль" в /servers/
# --------------------------------------------------------------------------- #

class TestPasswordColumnVisibility:
    """Столбец 'Пароль' должен присутствовать только для pass-admin/pass-lead."""

    def test_admin_sees_password_column(self, admin_client, sample_server):
        resp = admin_client.get('/servers/')
        assert resp.status_code == 200
        # Заголовок "Пароль" есть в шапке таблицы
        assert 'Пароль' in resp.get_data(as_text=True)

    def test_user_does_not_see_password_column(self, regular_client, sample_server):
        """pass-user не должен видеть столбец 'Пароль' в шапке таблицы."""
        # Создаём server через admin-фикстуру — нужен готовый sample_server
        body = regular_client.get('/servers/').get_data(as_text=True)
        # В шаблоне список заголовков не содержит "Пароль" при passwords_visible=False
        # Проверяем отсутствие именно заголовка колонки:
        assert '<th class="px-3 py-2">Пароль</th>' not in body

    def test_lead_sees_password_column(self, lead_client, sample_server):
        """pass-lead видит столбец 'Пароль' — как admin."""
        body = lead_client.get('/servers/').get_data(as_text=True)
        assert '<th class="px-3 py-2">Пароль</th>' in body


# --------------------------------------------------------------------------- #
# Видимость значения пароля в HTML
# --------------------------------------------------------------------------- #

class TestPasswordValueVisibility:
    """Значение пароля сервера должно присутствовать в HTML только для admin/lead."""

    def test_admin_sees_password_value(self, admin_client, sample_server):
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert 's3cret-root-pass' in body

    def test_user_does_not_see_password_value(self, regular_client, sample_server):
        """pass-user не должен видеть сам пароль в HTML списка."""
        body = regular_client.get('/servers/').get_data(as_text=True)
        assert 's3cret-root-pass' not in body

    def test_lead_sees_password_value(self, lead_client, sample_server):
        body = lead_client.get('/servers/').get_data(as_text=True)
        assert 's3cret-root-pass' in body


# --------------------------------------------------------------------------- #
# Детальная страница
# --------------------------------------------------------------------------- #

class TestDetailPage:
    """GET /servers/<id> — видимость пароля по ролям."""

    def test_user_detail_has_no_password(self, regular_client, sample_server):
        resp = regular_client.get(f'/servers/{sample_server.id}')
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 's3cret-root-pass' not in body
        # Должна быть индикация скрытия паролей
        assert 'Пароли скрыты' in body

    def test_admin_detail_has_password(self, admin_client, sample_server):
        body = admin_client.get(f'/servers/{sample_server.id}').get_data(as_text=True)
        assert 's3cret-root-pass' in body


# --------------------------------------------------------------------------- #
# inline edit endpoint — RBAC enforcement
# --------------------------------------------------------------------------- #

class TestInlineEditRbac:
    """POST /servers/<id>/field — только pass-admin/pass-lead могут менять пароли."""

    def test_user_cannot_edit_password_field(self, regular_client, sample_server):
        """pass-user не имеет права редактировать пароль → 403."""
        resp = regular_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'HACKED'},
        )
        assert resp.status_code == 403

    @pytest.mark.parametrize('field,value', [
        ('name', 'renamed-by-user'),
        ('ip_address', '203.0.113.10'),
        ('notes', 'changed'),
    ])
    def test_user_can_edit_non_password_fields(
        self, regular_client, sample_server, field, value,
    ):
        """pass-user может менять обычные поля → 200."""
        resp = regular_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': field, 'value': value},
        )
        assert resp.status_code == 200
        assert value in resp.get_data(as_text=True)

    def test_admin_can_edit_password_field(self, admin_client, sample_server):
        """pass-admin может редактировать пароль → 200 и значение меняется в БД."""
        from app.models import Server
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'new-pass-456'},
        )
        assert resp.status_code == 200
        # Проверяем, что значение реально записано (через гибридное свойство).
        from app.extensions import db
        with db.session.no_autoflush:
            refreshed = db.session.get(Server, sample_server.id)
            assert refreshed.password == 'new-pass-456'

"""Тесты HTMX-эндпоинтов: inline edit, toggle, домены."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Domain, Server


# --------------------------------------------------------------------------- #
# /servers/<id>/field — inline edit
# --------------------------------------------------------------------------- #

class TestInlineEditField:
    """POST /servers/<id>/field."""

    def test_edit_name_returns_new_value(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'name', 'value': 'fresh-name-007'},
        )
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'fresh-name-007' in body
        # В БД значение тоже обновлено
        refreshed = db.session.get(Server, sample_server.id)
        assert refreshed.name == 'fresh-name-007'

    @pytest.mark.parametrize('bad_field', [
        'unknown',
        '',
        'id',
        'created_at',
        'DROP TABLE servers;',
    ])
    def test_edit_unknown_field_returns_400(self, admin_client, sample_server, bad_field):
        """Любое поле не из whitelist → 400 Bad Request."""
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': bad_field, 'value': 'x'},
        )
        assert resp.status_code == 400

    def test_edit_ip_address(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'ip_address', 'value': '198.51.100.77'},
        )
        assert resp.status_code == 200
        assert '198.51.100.77' in resp.get_data(as_text=True)


# --------------------------------------------------------------------------- #
# /servers/<id>/toggle — boolean toggles
# --------------------------------------------------------------------------- #

class TestToggleField:
    """POST /servers/<id>/toggle."""

    @pytest.mark.parametrize('field,initial', [
        ('has_exim', True),
        ('has_squid', False),
        ('has_vpn', False),
        ('active', True),
    ])
    def test_toggle_boolean_field_in_db(
        self, admin_client, sample_server, field, initial,
    ):
        """Переключение должно поменять значение в БД на противоположное."""
        # Сбрасываем в начальное состояние (по параметру)
        server = db.session.get(Server, sample_server.id)
        setattr(server, field, initial)
        db.session.commit()

        resp = admin_client.post(
            f'/servers/{sample_server.id}/toggle',
            data={'field': field},
        )
        assert resp.status_code == 200

        refreshed = db.session.get(Server, sample_server.id)
        assert getattr(refreshed, field) is (not initial)

    def test_toggle_unknown_field_returns_400(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/toggle',
            data={'field': 'totally_invalid'},
        )
        assert resp.status_code == 400

    @pytest.mark.parametrize('field', [
        'name',          # не boolean — не входит в toggle whitelist
        'password',      # гибридное свойство
        '',
    ])
    def test_toggle_non_boolean_field_returns_400(
        self, admin_client, sample_server, field,
    ):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/toggle',
            data={'field': field},
        )
        assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# /servers/<id>/domains — add domain
# --------------------------------------------------------------------------- #

class TestAddDomain:
    """POST /servers/<id>/domains."""

    def test_add_domain_returns_200_and_creates_record(self, admin_client, sample_server):
        before = Domain.query.filter_by(server_id=sample_server.id).count()
        resp = admin_client.post(
            f'/servers/{sample_server.id}/domains',
            data={'domain': 'new-domain.example.net'},
        )
        assert resp.status_code == 200
        assert 'new-domain.example.net' in resp.get_data(as_text=True)
        after = Domain.query.filter_by(server_id=sample_server.id).count()
        assert after == before + 1

    def test_add_empty_domain_returns_400(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/domains',
            data={'domain': ''},
        )
        assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# /servers/domains/<id>/delete — delete domain
# --------------------------------------------------------------------------- #

class TestDeleteDomain:
    """POST /servers/domains/<id>/delete."""

    def test_delete_domain_returns_204(self, admin_client, sample_server):
        """Удаляем один из доменов sample_server → 204 и запись удалена."""
        domain = Domain.query.filter_by(server_id=sample_server.id).first()
        assert domain is not None
        did = domain.id

        resp = admin_client.post(f'/servers/domains/{did}/delete')
        assert resp.status_code == 204
        assert db.session.get(Domain, did) is None

    def test_delete_unknown_domain_returns_404(self, admin_client):
        resp = admin_client.post('/servers/domains/99999/delete')
        assert resp.status_code == 404

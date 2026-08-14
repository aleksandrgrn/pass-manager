"""Track C B1.2: правило видимости серверов.

Главный тест среза — сисадмин не видит чужие серверы. Проверяем и список,
и каждый server-scoped маршрут: список отфильтровать легко, а IDOR по прямой
ссылке остаётся открытым, если проверку забыли в обработчике.
"""
from __future__ import annotations

import json

import pytest

from app.extensions import db
from app.models import (
    AccessAssignment, Domain, ProvisioningJob, Server, ServerGroup,
)


@pytest.fixture()
def foreign_server(db):
    """Сервер чужой команды: admin_user в этой группе не состоит."""
    group = ServerGroup(name='foreign-group')
    db.session.add(group)
    db.session.commit()

    server = Server(name='vps-foreign-01', ip_address='203.0.113.99', group_id=group.id)
    db.session.add(server)
    db.session.commit()

    db.session.add(Domain(domain='foreign.example.com', server_id=server.id))
    db.session.commit()
    return server


def _foreign_job(server, user):
    job = ProvisioningJob(
        server_id=server.id,
        initiated_by=user.id,
        job_type='onboarding',
        status='running',
        steps_json=json.dumps({'steps': {}}),
    )
    db.session.add(job)
    db.session.commit()
    return job


class TestListVisibility:
    """Список серверов фильтруется по членству, а не по роли."""

    def test_admin_does_not_see_foreign_server(self, admin_client, sample_server, foreign_server):
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert 'vps-test-01' in body, 'свой сервер должен быть виден'
        assert 'vps-foreign-01' not in body

    def test_superadmin_sees_everything(self, superadmin_client, sample_server, foreign_server):
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert 'vps-test-01' in body
        assert 'vps-foreign-01' in body

    def test_admin_without_groups_sees_nothing(self, app, groupless_admin, sample_server):
        from tests.conftest import login_as
        client = app.test_client()
        login_as(client, 'groupless_test')

        body = client.get('/servers/').get_data(as_text=True)
        assert 'vps-test-01' not in body


class TestEmptyStateMessage:
    """B1.4: пустой список серверов различает две причины пустоты."""

    def test_groupless_user_sees_access_denied_message(self, app, groupless_admin):
        """Человек без единой группы — это не поломка, а следствие того,
        что ему ещё не выдали доступ (Р8: новичок появляется без групп)."""
        from tests.conftest import login_as
        client = app.test_client()
        login_as(client, 'groupless_test')

        body = client.get('/servers/').get_data(as_text=True)
        assert 'У вас нет доступа к серверам' in body
        assert 'Нет записей' not in body

    def test_user_with_group_sees_generic_empty_message(self, admin_client, default_group):
        """admin_user состоит в default_group, но в ней нет серверов —
        значит список пуст по обычной причине, не по отсутствию доступа."""
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert 'Нет записей' in body
        assert 'У вас нет доступа' not in body


class TestServerScopedRoutesRejectForeign:
    """IDOR по прямой ссылке: каждый маршрут обязан проверять доступ сам."""

    def test_detail_forbidden(self, admin_client, foreign_server):
        assert admin_client.get(f'/servers/{foreign_server.id}').status_code == 403

    def test_edit_forbidden(self, admin_client, foreign_server):
        assert admin_client.get(f'/servers/{foreign_server.id}/edit').status_code == 403

    def test_delete_forbidden(self, admin_client, foreign_server):
        resp = admin_client.post(f'/servers/{foreign_server.id}/delete')
        assert resp.status_code == 403
        assert db.session.get(Server, foreign_server.id) is not None

    def test_edit_field_forbidden(self, admin_client, foreign_server):
        resp = admin_client.post(f'/servers/{foreign_server.id}/field',
                                 data={'field': 'name', 'value': 'hacked'})
        assert resp.status_code == 403
        db.session.refresh(foreign_server)
        assert foreign_server.name == 'vps-foreign-01'

    def test_toggle_field_forbidden(self, admin_client, foreign_server):
        resp = admin_client.post(f'/servers/{foreign_server.id}/toggle',
                                 data={'field': 'active'})
        assert resp.status_code == 403

    def test_add_domain_forbidden(self, admin_client, foreign_server):
        resp = admin_client.post(f'/servers/{foreign_server.id}/domains',
                                 data={'domain': 'evil.example.com'})
        assert resp.status_code == 403

    def test_delete_domain_forbidden(self, admin_client, foreign_server):
        """Маршрут достаёт домен, а не сервер — проверять надо владельца."""
        domain = Domain.query.filter_by(server_id=foreign_server.id).first()
        resp = admin_client.post(f'/servers/domains/{domain.id}/delete')
        assert resp.status_code == 403
        assert db.session.get(Domain, domain.id) is not None


class TestProvisioningRoutesRejectForeign:
    """Pipeline меняет root-пароль на живой машине — чужой job гонять нельзя."""

    def test_step_forbidden(self, admin_client, foreign_server, superadmin_user):
        job = _foreign_job(foreign_server, superadmin_user)
        assert admin_client.post(f'/provisioning/jobs/{job.id}/step').status_code == 403

    def test_restart_forbidden(self, admin_client, foreign_server, superadmin_user):
        job = _foreign_job(foreign_server, superadmin_user)
        assert admin_client.post(f'/provisioning/jobs/{job.id}/restart').status_code == 403

    def test_job_page_forbidden(self, admin_client, foreign_server, superadmin_user):
        job = _foreign_job(foreign_server, superadmin_user)
        assert admin_client.get(f'/provisioning/jobs/{job.id}').status_code == 403


class TestCreateLandsInGroup:
    """Заведённый админом сервер обязан попасть в его группу.

    Иначе он создаётся «ничьим», и создатель тут же теряет его из списка —
    ровно та регрессия, которую приносит правило видимости, если про неё забыть.
    """

    def test_admin_created_server_stays_visible(self, admin_client, default_group):
        resp = admin_client.post('/servers/new', data={
            'name': 'vps-created-01',
            'ip_address': '198.51.100.5',
            'password': 'Init-Pass-123!',
            'group_id': str(default_group.id),
        })
        assert resp.status_code == 302

        server = Server.query.filter_by(name='vps-created-01').first()
        assert server.group_id == default_group.id
        assert 'vps-created-01' in admin_client.get('/servers/').get_data(as_text=True)

    def test_group_without_flag_cannot_create(self, app, db, groupless_admin, superadmin_user):
        """Р6: возможность заводить серверы — свойство группы, а не роли."""
        from app.models import ServerGroupMembership
        from tests.conftest import login_as

        quiet = ServerGroup(name='quiet-group', can_create_servers=False)
        db.session.add(quiet)
        db.session.commit()
        db.session.add(ServerGroupMembership(
            user_id=groupless_admin.id, group_id=quiet.id, added_by=superadmin_user.id,
        ))
        db.session.commit()

        client = app.test_client()
        login_as(client, 'groupless_test')
        assert client.get('/servers/new').status_code == 403

    def test_admin_cannot_move_server_between_groups(self, admin_client, sample_server, db):
        """Р7: перекладывать сервер в другую команду может только суперадмин."""
        other = ServerGroup(name='other-group')
        db.session.add(other)
        db.session.commit()
        original_group_id = sample_server.group_id

        resp = admin_client.post(f'/servers/{sample_server.id}/edit', data={
            'name': sample_server.name,
            'group_id': str(other.id),
        })
        assert resp.status_code == 302

        db.session.refresh(sample_server)
        assert sample_server.group_id == original_group_id

    def test_superadmin_can_create_without_group(self, superadmin_client):
        resp = superadmin_client.post('/servers/new', data={
            'name': 'vps-orphan-01',
            'ip_address': '198.51.100.6',
            'password': 'Init-Pass-123!',
            'group_id': '0',
        })
        assert resp.status_code == 302
        assert Server.query.filter_by(name='vps-orphan-01').first().group_id is None


class TestPointGrant:
    """Точечная выдача открывает чужой сервер, отзыв — закрывает обратно."""

    def _grant(self, server, user, granter, state='active'):
        assignment = AccessAssignment(
            server_id=server.id, user_id=user.id,
            state=state, granted_by=granter.id,
        )
        db.session.add(assignment)
        db.session.commit()
        return assignment

    def test_active_grant_makes_foreign_server_visible(
        self, admin_client, admin_user, superadmin_user, foreign_server,
    ):
        self._grant(foreign_server, admin_user, superadmin_user)

        body = admin_client.get('/servers/').get_data(as_text=True)
        assert 'vps-foreign-01' in body
        assert admin_client.get(f'/servers/{foreign_server.id}').status_code == 200

    def test_revoked_grant_hides_server_again(
        self, admin_client, admin_user, superadmin_user, foreign_server,
    ):
        """Инвариант: видимость смотрит на активные выдачи, поэтому отзыв
        убирает сервер сам собой — отдельного механизма нет и не нужно."""
        assignment = self._grant(foreign_server, admin_user, superadmin_user)
        assignment.state = 'revoked'
        db.session.commit()

        body = admin_client.get('/servers/').get_data(as_text=True)
        assert 'vps-foreign-01' not in body
        assert admin_client.get(f'/servers/{foreign_server.id}').status_code == 403

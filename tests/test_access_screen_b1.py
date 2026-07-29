"""Track C B1.3: экран управления группами для суперадмина.

Главное, что здесь проверяется: маршрут не для admin (403 на GET и на КАЖДОЙ
мутации — забыть декоратор хоть на одном POST'е обнуляет весь смысл среза),
пункт меню виден только суперадмину, и мутации реально меняют то, что
показывает /servers/ (правило видимости уже покрыто test_visibility_b1.py,
здесь — только то, что экран управления группами дёргает его правильно).
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Server, ServerGroup, ServerGroupMembership
from tests.conftest import login_as


@pytest.fixture()
def other_group(db):
    """Отдельная группа с одним сервером — приписка/вывод меняют её видимость."""
    group = ServerGroup(name='other-group')
    db.session.add(group)
    db.session.commit()

    server = Server(name='vps-other-01', ip_address='203.0.113.50', group_id=group.id)
    db.session.add(server)
    db.session.commit()
    return group


class TestSuperadminOnly:
    """Забыть role_required хоть на одном маршруте — дыра. Проверяем все."""

    def test_admin_forbidden_on_index(self, admin_client):
        assert admin_client.get('/access/').status_code == 403

    def test_admin_forbidden_on_create_group(self, admin_client):
        resp = admin_client.post('/access/groups', data={'name': 'sneaky'})
        assert resp.status_code == 403
        assert ServerGroup.query.filter_by(name='sneaky').first() is None

    def test_admin_forbidden_on_delete_group(self, admin_client, default_group):
        resp = admin_client.post(f'/access/groups/{default_group.id}/delete')
        assert resp.status_code == 403
        assert db.session.get(ServerGroup, default_group.id) is not None

    def test_admin_forbidden_on_toggle_create(self, admin_client, default_group):
        resp = admin_client.post(f'/access/groups/{default_group.id}/toggle-create')
        assert resp.status_code == 403

    def test_admin_forbidden_on_add_membership(self, admin_client, admin_user, default_group):
        resp = admin_client.post(
            f'/access/users/{admin_user.id}/groups',
            data={'group_id': default_group.id},
        )
        assert resp.status_code == 403

    def test_admin_forbidden_on_remove_membership(self, admin_client, admin_user, default_group):
        resp = admin_client.post(
            f'/access/users/{admin_user.id}/groups/{default_group.id}/delete'
        )
        assert resp.status_code == 403
        assert ServerGroupMembership.query.filter_by(
            user_id=admin_user.id, group_id=default_group.id,
        ).first() is not None


class TestMenuVisibility:
    def test_admin_does_not_see_access_menu_item(self, admin_client):
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert '/access/' not in body

    def test_superadmin_sees_access_menu_item(self, superadmin_client):
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert '/access/' in body


class TestCreateGroup:
    def test_superadmin_creates_group(self, superadmin_client):
        resp = superadmin_client.post('/access/groups', data={
            'name': 'new-team', 'can_create_servers': 'on',
        })
        assert resp.status_code == 200

        group = ServerGroup.query.filter_by(name='new-team').first()
        assert group is not None
        assert group.can_create_servers is True

    def test_duplicate_group_name_shows_message_not_500(self, superadmin_client, default_group):
        resp = superadmin_client.post('/access/groups', data={'name': default_group.name})
        assert resp.status_code == 200
        assert ServerGroup.query.filter_by(name=default_group.name).count() == 1


class TestMembershipChangesVisibility:
    """Приписка/вывод из группы меняет то, что человек видит на /servers/."""

    def test_assign_to_group_grants_visibility(
        self, app, superadmin_client, groupless_admin, other_group,
    ):
        resp = superadmin_client.post(
            f'/access/users/{groupless_admin.id}/groups',
            data={'group_id': other_group.id},
        )
        assert resp.status_code == 200
        assert ServerGroupMembership.query.filter_by(
            user_id=groupless_admin.id, group_id=other_group.id,
        ).first() is not None

        client = app.test_client()
        login_as(client, 'groupless_test')
        body = client.get('/servers/').get_data(as_text=True)
        assert 'vps-other-01' in body

    def test_remove_from_group_revokes_visibility(
        self, app, superadmin_client, groupless_admin, other_group, superadmin_user,
    ):
        db.session.add(ServerGroupMembership(
            user_id=groupless_admin.id, group_id=other_group.id, added_by=superadmin_user.id,
        ))
        db.session.commit()

        resp = superadmin_client.post(
            f'/access/users/{groupless_admin.id}/groups/{other_group.id}/delete'
        )
        assert resp.status_code == 200
        assert ServerGroupMembership.query.filter_by(
            user_id=groupless_admin.id, group_id=other_group.id,
        ).first() is None

        client = app.test_client()
        login_as(client, 'groupless_test')
        body = client.get('/servers/').get_data(as_text=True)
        assert 'vps-other-01' not in body

    def test_duplicate_membership_does_not_crash(
        self, superadmin_client, groupless_admin, other_group,
    ):
        """uq_user_group ловится приложением, а не роняет его IntegrityError'ом."""
        first = superadmin_client.post(
            f'/access/users/{groupless_admin.id}/groups',
            data={'group_id': other_group.id},
        )
        assert first.status_code == 200

        second = superadmin_client.post(
            f'/access/users/{groupless_admin.id}/groups',
            data={'group_id': other_group.id},
        )
        assert second.status_code == 200

        assert ServerGroupMembership.query.filter_by(
            user_id=groupless_admin.id, group_id=other_group.id,
        ).count() == 1


class TestToggleCanCreateServers:
    """Р6: переключатель на экране решает, доступна ли человеку форма заведения.

    Единственный рычаг этого экрана, последствия которого видны за его пределами —
    поэтому проверяем не сам флаг в базе, а эффект на /servers/new.
    """

    def test_toggle_opens_and_closes_server_creation(
        self, app, superadmin_client, admin_user, default_group,
    ):
        admin = app.test_client()
        login_as(admin, 'admin_test')

        # default_group заведена с can_create_servers=True — форма открыта
        assert admin.get('/servers/new').status_code == 200

        # суперадмин снимает флажок
        resp = superadmin_client.post(f'/access/groups/{default_group.id}/toggle-create')
        assert resp.status_code == 200
        assert default_group.can_create_servers is False
        assert admin.get('/servers/new').status_code == 403

        # и возвращает обратно
        superadmin_client.post(f'/access/groups/{default_group.id}/toggle-create')
        assert default_group.can_create_servers is True
        assert admin.get('/servers/new').status_code == 200


class TestDeleteGroup:
    def test_server_survives_group_deletion(self, superadmin_client, other_group):
        server = Server.query.filter_by(name='vps-other-01').first()
        server_id = server.id

        resp = superadmin_client.post(f'/access/groups/{other_group.id}/delete')
        assert resp.status_code == 200

        assert db.session.get(ServerGroup, other_group.id) is None
        survivor = db.session.get(Server, server_id)
        assert survivor is not None
        assert survivor.group_id is None

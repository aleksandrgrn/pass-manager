"""FIX-C2-2b: self-grant access to a server using a personal key."""
from unittest.mock import patch

from app.models import AccessAssignment, Server, ServerGroup


def test_self_grant_generates_and_deploys_key(app, db, admin_client, admin_user, sample_server):
    sample_server.vps_manager_server_id = 42
    db.session.commit()

    with patch('app.servers.views.vps_client.generate_key', return_value={'success': True, 'id': 7}) as generate_key, \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': True}) as deploy_key:
        response = admin_client.post(f'/servers/{sample_server.id}/grant-self')

    assert response.status_code == 302
    generate_key.assert_called_once_with(name=admin_user.username, key_type='rsa')
    deploy_key.assert_called_once_with(key_id=7, server_id=42)
    assignment = AccessAssignment.query.one()
    assert assignment.state == 'active'
    assert assignment.granted_by == admin_user.id
    assert assignment.vps_manager_key_id == 7
    assert admin_user.vps_manager_key_id == 7


def test_self_grant_uses_existing_key(app, db, admin_client, admin_user, sample_server):
    sample_server.vps_manager_server_id = 42
    admin_user.vps_manager_key_id = 7
    db.session.commit()

    with patch('app.servers.views.vps_client.generate_key') as generate_key, \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': True}) as deploy_key:
        response = admin_client.post(f'/servers/{sample_server.id}/grant-self')

    assert response.status_code == 302
    generate_key.assert_not_called()
    deploy_key.assert_called_once_with(key_id=7, server_id=42)


def test_self_grant_rejects_unconnected_server(app, db, admin_client, sample_server):
    with patch('app.servers.views.vps_client.generate_key') as generate_key, \
            patch('app.servers.views.vps_client.deploy_key') as deploy_key:
        response = admin_client.post(f'/servers/{sample_server.id}/grant-self')

    assert response.status_code == 302
    generate_key.assert_not_called()
    deploy_key.assert_not_called()
    assert AccessAssignment.query.count() == 0


def test_self_grant_is_idempotent(app, db, admin_client, sample_server):
    sample_server.vps_manager_server_id = 42
    db.session.commit()

    with patch('app.servers.views.vps_client.generate_key', return_value={'success': True, 'id': 7}), \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': True}) as deploy_key:
        first = admin_client.post(f'/servers/{sample_server.id}/grant-self')
        second = admin_client.post(f'/servers/{sample_server.id}/grant-self')

    assert first.status_code == 302
    assert second.status_code == 302
    assert AccessAssignment.query.count() == 1
    assert deploy_key.call_count == 1


def test_self_grant_deploy_failure_does_not_create_assignment(app, db, admin_client, sample_server):
    sample_server.vps_manager_server_id = 42
    db.session.commit()

    with patch('app.servers.views.vps_client.generate_key', return_value={'success': True, 'id': 7}), \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': False, 'message': 'down'}):
        response = admin_client.post(f'/servers/{sample_server.id}/grant-self')

    assert response.status_code == 302
    assert AccessAssignment.query.count() == 0


def test_self_grant_is_forbidden_on_foreign_server(
    app, db, admin_client, admin_user, superadmin_user,
):
    foreign_group = ServerGroup(name='foreign-group', can_create_servers=True)
    db.session.add(foreign_group)
    db.session.commit()
    server = Server(
        group_id=foreign_group.id, name='foreign-server', ip_address='192.0.2.20',
    )
    db.session.add(server)
    db.session.commit()
    db.session.add(AccessAssignment(
        server_id=server.id, user_id=admin_user.id, state='active',
        granted_by=superadmin_user.id,
    ))
    db.session.commit()

    detail = admin_client.get(f'/servers/{server.id}')
    response = admin_client.post(f'/servers/{server.id}/grant-self')

    assert detail.status_code == 200
    assert response.status_code == 403
    assert 'Выдать себе доступ' not in detail.get_data(as_text=True)


def test_self_grant_button_depends_on_connection(app, db, admin_client, sample_server):
    sample_server.vps_manager_server_id = 42
    db.session.commit()
    connected = admin_client.get(f'/servers/{sample_server.id}')

    sample_server.vps_manager_server_id = None
    db.session.commit()
    unconnected = admin_client.get(f'/servers/{sample_server.id}')

    assert 'Выдать себе доступ' in connected.get_data(as_text=True)
    assert 'Выдать себе доступ' not in unconnected.get_data(as_text=True)
    assert 'Сервер не подключён к VPS Manager — доступ выдать нельзя' in unconnected.get_data(as_text=True)

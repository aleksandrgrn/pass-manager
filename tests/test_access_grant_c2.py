"""FIX-C2-2b: self-grant access to a server using a personal key."""
import io
import zipfile
from datetime import datetime
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
    # Якорь — форма выдачи, а не подпись кнопки: ту же фразу произносит
    # обучающая модалка, которая рендерится на каждой странице.
    assert f'/servers/{server.id}/grant-self' not in detail.get_data(as_text=True)


def test_self_grant_button_depends_on_connection(app, db, admin_client, sample_server):
    sample_server.vps_manager_server_id = 42
    db.session.commit()
    connected = admin_client.get(f'/servers/{sample_server.id}')

    sample_server.vps_manager_server_id = None
    db.session.commit()
    unconnected = admin_client.get(f'/servers/{sample_server.id}')

    # Якорь — форма выдачи, а не подпись кнопки: ту же фразу произносит
    # обучающая модалка, которая рендерится на каждой странице.
    action = f'/servers/{sample_server.id}/grant-self'
    assert action in connected.get_data(as_text=True)
    assert action not in unconnected.get_data(as_text=True)
    assert 'Сервер не подключён к VPS Manager — доступ выдать нельзя' in unconnected.get_data(as_text=True)


def test_access_screen_is_open_to_admin_without_inventory(app, admin_client):
    response = admin_client.get('/access/')

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'Мой ключ' in body
    assert 'Группы' not in body


def test_superadmin_sees_access_inventory(app, superadmin_client):
    response = superadmin_client.get('/access/')

    assert response.status_code == 200
    assert 'Группы' in response.get_data(as_text=True)


def test_access_link_is_visible_to_admin(app, admin_client):
    response = admin_client.get('/servers/')

    assert response.status_code == 200
    assert 'href="/access/"' in response.get_data(as_text=True)


def test_admin_can_download_personal_key_once(app, db, admin_client, admin_user):
    admin_user.vps_manager_key_id = 7
    db.session.commit()

    with patch(
        'app.access.views.vps_client.get_private_key',
        return_value={'success': True, 'private_key': 'PEMDATA'},
    ) as get_private_key, patch(
        'app.access.views.vps_client.get_private_key_ppk',
        return_value={'success': True, 'private_key_ppk': 'PPKDATA'},
    ) as get_private_key_ppk:
        response = admin_client.post('/access/key/download')

    assert response.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(response.data))
    assert sorted(archive.namelist()) == ['id_rsa', 'id_rsa.ppk']
    assert archive.read('id_rsa') == b'PEMDATA'
    assert archive.read('id_rsa.ppk') == b'PPKDATA'
    assert 'attachment' in response.headers['Content-Disposition']
    assert admin_user.key_downloaded_at is not None
    get_private_key.assert_called_once_with(7)
    get_private_key_ppk.assert_called_once_with(7)


def test_second_key_download_is_rejected_without_client_call(
    app, db, admin_client, admin_user,
):
    admin_user.vps_manager_key_id = 7
    db.session.commit()

    with patch(
        'app.access.views.vps_client.get_private_key',
        return_value={'success': True, 'private_key': 'PEMDATA'},
    ) as get_private_key, patch(
        'app.access.views.vps_client.get_private_key_ppk',
        return_value={'success': True, 'private_key_ppk': 'PPKDATA'},
    ):
        first = admin_client.post('/access/key/download')
        second = admin_client.post('/access/key/download')

    assert first.status_code == 200
    assert second.status_code == 302
    get_private_key.assert_called_once_with(7)


def test_key_download_failure_does_not_consume_attempt(
    app, db, admin_client, admin_user,
):
    admin_user.vps_manager_key_id = 7
    db.session.commit()

    with patch(
        'app.access.views.vps_client.get_private_key',
        return_value={'success': False, 'message': 'down'},
    ) as get_private_key, patch(
        'app.access.views.vps_client.get_private_key_ppk',
        return_value={'success': True, 'private_key_ppk': 'PPKDATA'},
    ) as get_private_key_ppk:
        response = admin_client.post('/access/key/download')

    assert response.status_code == 302
    assert admin_user.key_downloaded_at is None
    get_private_key.assert_called_once_with(7)
    get_private_key_ppk.assert_not_called()


def test_missing_key_does_not_call_vps_manager(app, db, admin_client, admin_user):
    admin_user.vps_manager_key_id = None
    db.session.commit()

    with patch('app.access.views.vps_client.get_private_key') as get_private_key:
        response = admin_client.post('/access/key/download')

    assert response.status_code == 302
    assert admin_user.key_downloaded_at is None
    get_private_key.assert_not_called()


def test_self_grant_key_generation_failure_does_not_deploy_or_assign(
    app, db, admin_client, admin_user, sample_server,
):
    sample_server.vps_manager_server_id = 42
    db.session.commit()

    with patch(
        'app.servers.views.vps_client.generate_key',
        return_value={'success': False, 'message': 'нет связи'},
    ), patch('app.servers.views.vps_client.deploy_key') as deploy_key:
        response = admin_client.post(f'/servers/{sample_server.id}/grant-self')

    assert response.status_code == 302
    deploy_key.assert_not_called()
    assert AccessAssignment.query.count() == 0
    assert admin_user.vps_manager_key_id is None


def test_key_download_requires_login(app, client):
    """Единственный маршрут, отдающий приватный ключ, закрыт от анонима."""
    response = client.post('/access/key/download')

    assert response.status_code == 302
    assert '/auth/login' in response.headers['Location']


def test_superadmin_can_reset_key_download_flag(
    app, db, admin_user, superadmin_client,
):
    admin_user.vps_manager_key_id = 7
    admin_user.key_downloaded_at = datetime.utcnow()
    db.session.commit()

    response = superadmin_client.post(f'/access/users/{admin_user.id}/key/reset')

    assert response.status_code == 200
    assert 'Группы' in response.get_data(as_text=True)
    assert admin_user.key_downloaded_at is None


def test_admin_cannot_reset_key_download_flag(
    app, db, admin_user, admin_client,
):
    admin_user.vps_manager_key_id = 7
    admin_user.key_downloaded_at = datetime.utcnow()
    db.session.commit()

    response = admin_client.post(f'/access/users/{admin_user.id}/key/reset')

    assert response.status_code == 403
    assert admin_user.key_downloaded_at is not None


def test_key_download_works_again_after_reset(
    app, db, admin_user, admin_client, superadmin_client,
):
    admin_user.vps_manager_key_id = 7
    admin_user.key_downloaded_at = datetime.utcnow()
    db.session.commit()

    reset_response = superadmin_client.post(f'/access/users/{admin_user.id}/key/reset')
    assert reset_response.status_code == 200

    with patch(
        'app.access.views.vps_client.get_private_key',
        return_value={'success': True, 'private_key': 'PEMDATA'},
    ), patch(
        'app.access.views.vps_client.get_private_key_ppk',
        return_value={'success': True, 'private_key_ppk': 'PPKDATA'},
    ):
        response = admin_client.post('/access/key/download')

    assert response.status_code == 200
    archive = zipfile.ZipFile(io.BytesIO(response.data))
    assert sorted(archive.namelist()) == ['id_rsa', 'id_rsa.ppk']
    assert archive.read('id_rsa') == b'PEMDATA'
    assert archive.read('id_rsa.ppk') == b'PPKDATA'


def test_reset_button_is_visible_only_when_download_was_used(
    app, db, admin_user, superadmin_client,
):
    admin_user.vps_manager_key_id = 7
    admin_user.key_downloaded_at = datetime.utcnow()
    db.session.commit()

    downloaded = superadmin_client.get('/access/')

    admin_user.key_downloaded_at = None
    db.session.commit()
    not_downloaded = superadmin_client.get('/access/')

    assert f'/access/users/{admin_user.id}/key/reset' in downloaded.get_data(as_text=True)
    assert f'/access/users/{admin_user.id}/key/reset' not in not_downloaded.get_data(as_text=True)


def test_key_download_ppk_failure_does_not_consume_attempt(
    app, db, admin_client, admin_user,
):
    admin_user.vps_manager_key_id = 7
    db.session.commit()

    with patch(
        'app.access.views.vps_client.get_private_key',
        return_value={'success': True, 'private_key': 'PEMDATA'},
    ), patch(
        'app.access.views.vps_client.get_private_key_ppk',
        return_value={'success': False, 'message': 'puttygen'},
    ):
        response = admin_client.post('/access/key/download')

    assert response.status_code == 302
    assert admin_user.key_downloaded_at is None


def test_key_archive_contents_are_described(app, db, admin_client, admin_user):
    admin_user.vps_manager_key_id = 7
    admin_user.key_downloaded_at = None
    db.session.commit()

    response = admin_client.get('/access/')

    assert response.status_code == 200
    assert 'id_rsa.ppk для PuTTY' in response.get_data(as_text=True)

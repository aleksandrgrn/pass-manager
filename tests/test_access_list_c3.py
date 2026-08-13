"""FIX-C3-1: access indicator in the server list."""
from unittest.mock import patch

from app.models import AccessAssignment, User


def test_list_shows_green_key_when_access_granted(
    app, db, admin_client, admin_user, sample_server,
):
    db.session.add(AccessAssignment(
        server_id=sample_server.id,
        user_id=admin_user.id,
        state='active',
        granted_by=admin_user.id,
    ))
    db.session.commit()

    response = admin_client.get('/servers/')

    assert response.status_code == 200
    assert 'title="Доступ выдан"' in response.get_data(as_text=True)


def test_list_shows_grant_button_when_connected(
    app, db, admin_client, sample_server,
):
    sample_server.vps_manager_server_id = 42
    db.session.commit()

    response = admin_client.get('/servers/')

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert f'hx-post="/servers/{sample_server.id}/grant-self"' in body
    assert f'hx-confirm="Выдать себе доступ на «{sample_server.name}»?"' in body


def test_list_shows_faded_key_when_not_connected(
    app, admin_client, sample_server,
):
    response = admin_client.get('/servers/')

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'title="Сервер не подключён к VPS Manager"' in body
    assert 'grant-self' not in body


def test_list_shows_people_count_to_superadmin(
    app, db, admin_user, superadmin_client, sample_server,
):
    second_user = User(
        username='second_admin',
        display_name='Second Admin',
        role='admin',
        is_local=True,
        is_active=True,
    )
    second_user.set_password('pass123')
    db.session.add(second_user)
    db.session.commit()
    db.session.add_all([
        AccessAssignment(
            server_id=sample_server.id,
            user_id=admin_user.id,
            state='active',
            granted_by=admin_user.id,
        ),
        AccessAssignment(
            server_id=sample_server.id,
            user_id=second_user.id,
            state='active',
            granted_by=admin_user.id,
        ),
    ])
    db.session.commit()

    response = superadmin_client.get('/servers/')

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert '>Доступ</th>' in body
    assert '2&nbsp;чел.' in body


def test_list_has_no_key_icon_for_superadmin(
    app, superadmin_client, sample_server,
):
    response = superadmin_client.get('/servers/')

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'title="Доступ выдан"' not in body
    assert 'grant-self' not in body


def test_grant_from_list_returns_row_with_green_key(
    app, db, admin_client, sample_server,
):
    sample_server.vps_manager_server_id = 42
    db.session.commit()

    with patch(
        'app.servers.views.vps_client.generate_key',
        return_value={'success': True, 'id': 7},
    ), patch(
        'app.servers.views.vps_client.deploy_key',
        return_value={'success': True},
    ) as deploy_key:
        response = admin_client.post(
            f'/servers/{sample_server.id}/grant-self',
            headers={'HX-Request': 'true'},
        )

    assert response.status_code == 200
    assert 'title="Доступ выдан"' in response.get_data(as_text=True)
    deploy_key.assert_called_once()
    assert AccessAssignment.query.count() == 1


def test_grant_from_list_failure_redirects_via_hx_header(
    app, db, admin_client, sample_server,
):
    sample_server.vps_manager_server_id = 42
    db.session.commit()

    with patch(
        'app.servers.views.vps_client.generate_key',
        return_value={'success': True, 'id': 7},
    ), patch(
        'app.servers.views.vps_client.deploy_key',
        return_value={'success': False, 'message': 'down'},
    ):
        response = admin_client.post(
            f'/servers/{sample_server.id}/grant-self',
            headers={'HX-Request': 'true'},
        )

    assert response.status_code == 204
    assert response.headers['HX-Redirect'] == f'/servers/{sample_server.id}'
    assert AccessAssignment.query.count() == 0


def test_row_keeps_key_icon_after_toggle(
    app, db, admin_client, admin_user, sample_server,
):
    db.session.add(AccessAssignment(
        server_id=sample_server.id,
        user_id=admin_user.id,
        state='active',
        granted_by=admin_user.id,
    ))
    db.session.commit()

    response = admin_client.post(
        f'/servers/{sample_server.id}/toggle',
        data={'field': 'active'},
        headers={'HX-Request': 'true'},
    )

    assert response.status_code == 200
    assert 'title="Доступ выдан"' in response.get_data(as_text=True)

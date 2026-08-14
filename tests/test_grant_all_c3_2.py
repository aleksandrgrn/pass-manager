"""FIX-C3-2: массовая самовыдача доступа на все свои серверы + role="img"."""
import json
from unittest.mock import patch

from app.models import AccessAssignment, ProvisioningJob, Server, User
from tests.conftest import login_as


def _server(db, group, name, vps_manager_server_id=42):
    server = Server(group_id=group.id, name=name, vps_manager_server_id=vps_manager_server_id)
    db.session.add(server)
    db.session.commit()
    return server


def test_start_grant_all_creates_running_job(app, db, admin_client, admin_user, default_group):
    _server(db, default_group, 'srv-1')
    _server(db, default_group, 'srv-2')

    response = admin_client.post('/access/grant-self/all')

    assert response.status_code == 302
    job = ProvisioningJob.query.one()
    assert job.job_type == 'self_grant_batch'
    assert job.initiated_by == admin_user.id
    assert job.status == 'running'
    assert f'/access/grant-self/all/{job.id}' in response.headers['Location']


def test_start_grant_all_with_nothing_to_do_skips_job(app, db, admin_client):
    response = admin_client.post('/access/grant-self/all')

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/access/')
    assert ProvisioningJob.query.count() == 0


def test_start_grant_all_reuses_running_job(app, db, admin_client, default_group):
    _server(db, default_group, 'srv-1')

    first = admin_client.post('/access/grant-self/all')
    second = admin_client.post('/access/grant-self/all')

    assert first.headers['Location'] == second.headers['Location']
    assert ProvisioningJob.query.count() == 1


def test_grant_all_steps_through_all_servers_and_finishes(app, db, admin_client, default_group):
    _server(db, default_group, 'srv-1')
    _server(db, default_group, 'srv-2')
    admin_client.post('/access/grant-self/all')
    job = ProvisioningJob.query.one()

    with patch('app.servers.views.vps_client.generate_key', return_value={'success': True, 'id': 7}), \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': True}):
        admin_client.post(f'/access/grant-self/all/{job.id}/step')
        response = admin_client.post(f'/access/grant-self/all/{job.id}/step')

    db.session.refresh(job)
    assert job.status == 'success'
    assert AccessAssignment.query.count() == 2
    results = json.loads(job.steps_json)['results']
    assert len(results) == 2
    assert {r['status'] for r in results} == {'granted'}
    assert 'Готово' in response.get_data(as_text=True)


def test_grant_all_skips_server_with_existing_access(app, db, admin_client, admin_user, default_group):
    already = _server(db, default_group, 'srv-already')
    todo = _server(db, default_group, 'srv-todo')
    db.session.add(AccessAssignment(
        server_id=already.id, user_id=admin_user.id, state='active', granted_by=admin_user.id,
    ))
    db.session.commit()

    admin_client.post('/access/grant-self/all')
    job = ProvisioningJob.query.one()

    with patch('app.servers.views.vps_client.generate_key', return_value={'success': True, 'id': 7}), \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': True}) as deploy_key:
        admin_client.post(f'/access/grant-self/all/{job.id}/step')

    db.session.refresh(job)
    assert job.status == 'success'
    results = json.loads(job.steps_json)['results']
    assert len(results) == 1
    assert results[0]['server_id'] == todo.id
    deploy_key.assert_called_once()


def test_grant_all_skips_archived_server(app, db, admin_client, default_group):
    """Архивные записи в очередь не попадают.

    Архивный создаётся первым и получает меньший id: выборка идёт
    `order_by(Server.id)`, поэтому без фильтра он был бы взят раньше живого и
    тест упал бы на первом же шаге, а не пропустил проверку молча.

    На боевом парке таких записей 194 против 12 живых, и каждая стоила
    отдельного круга опроса.
    """
    archived = _server(db, default_group, 'srv-archived')
    archived.active = False
    db.session.commit()
    live = _server(db, default_group, 'srv-live')

    admin_client.post('/access/grant-self/all')
    job = ProvisioningJob.query.one()

    with patch('app.servers.views.vps_client.generate_key', return_value={'success': True, 'id': 7}), \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': True}):
        admin_client.post(f'/access/grant-self/all/{job.id}/step')

    db.session.refresh(job)
    assert job.status == 'success'
    results = json.loads(job.steps_json)['results']
    assert [r['server_id'] for r in results] == [live.id]


def test_grant_all_records_failure_without_looping_forever(app, db, admin_client, default_group):
    _server(db, default_group, 'srv-bad')

    admin_client.post('/access/grant-self/all')
    job = ProvisioningJob.query.one()

    with patch('app.servers.views.vps_client.generate_key', return_value={'success': True, 'id': 7}), \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': False, 'message': 'down'}):
        admin_client.post(f'/access/grant-self/all/{job.id}/step')
        admin_client.post(f'/access/grant-self/all/{job.id}/step')

    db.session.refresh(job)
    assert job.status == 'success'
    results = json.loads(job.steps_json)['results']
    assert len(results) == 1
    assert results[0]['status'] == 'deploy_failed'
    assert AccessAssignment.query.count() == 0


def test_grant_all_job_forbidden_for_another_user(app, db, admin_client, default_group):
    _server(db, default_group, 'srv-1')
    admin_client.post('/access/grant-self/all')
    job = ProvisioningJob.query.one()

    other = User(username='other_admin', display_name='Other', role='admin', is_local=True, is_active=True)
    other.set_password('pass123')
    db.session.add(other)
    db.session.commit()

    other_client = app.test_client()
    login_as(other_client, 'other_admin')

    progress = other_client.get(f'/access/grant-self/all/{job.id}')
    step = other_client.post(f'/access/grant-self/all/{job.id}/step')

    assert progress.status_code == 403
    assert step.status_code == 403


def test_grant_all_button_on_access_page(app, admin_client):
    response = admin_client.get('/access/')
    body = response.get_data(as_text=True)

    assert 'action="/access/grant-self/all"' in body
    assert 'Выдать себе доступ на все мои серверы' in body


def test_key_icon_has_accessible_role_when_granted(app, db, admin_client, admin_user, sample_server):
    sample_server.vps_manager_server_id = 42
    db.session.add(AccessAssignment(
        server_id=sample_server.id, user_id=admin_user.id, state='active', granted_by=admin_user.id,
    ))
    db.session.commit()

    response = admin_client.get('/servers/')

    assert 'role="img"' in response.get_data(as_text=True)


def test_key_icon_has_accessible_role_when_not_connected(app, db, admin_client, sample_server):
    sample_server.vps_manager_server_id = None
    db.session.commit()

    response = admin_client.get('/servers/')

    assert 'role="img"' in response.get_data(as_text=True)

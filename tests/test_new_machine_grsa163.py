"""GRSA-163, этап B: хостер выдал новую машину вместо старой.

Мокаем vps_client, rotate_root и запись файла ключа — реальных машин нет.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from app.models import ProvisioningJob, Server
from app.security import decrypt
from app.services.provisioning import restart_job, run_next_step, start_new_machine

FORM = {'ip_address': ' 198.51.100.7 ', 'ssh_port': '22', 'password': 'Hoster-New-1'}
E13_OK = {
    'success': True,
    'server': {'ip_address': '198.51.100.7', 'ssh_port': 22},
    'redeploy': {'total': 2, 'deployed': 1,
                 'failed': [{'key_id': 5, 'key_name': 'alice', 'message': 'disk full'}]},
}


def _make_server(db, group, vps_id=42, status='ready'):
    server = Server(name='vps-moved-01', ip_address='192.0.2.60', ssh_username='root',
                    ssh_port=2233, active=True, group_id=group.id,
                    vps_manager_server_id=vps_id, provisioning_status=status,
                    bootstrap_request_id='old-request-id')
    server.password = 'Old-Machine-Root'
    db.session.add(server)
    db.session.commit()
    return server


def _state(job):
    db_job = ProvisioningJob.query.get(job.id)
    return json.loads(db_job.steps_json)


def _run_all(job, e13_result):
    with patch('app.services.provisioning.vps_client.rebootstrap_server',
               return_value=e13_result) as mock_e13, \
            patch('app.services.provisioning.vps_client.add_server') as mock_add, \
            patch('app.services.provisioning.vps_client.get_access_key',
                  return_value={'success': True, 'private_key': 'PEM'}), \
            patch('app.services.provisioning._write_key_file'), \
            patch('app.services.provisioning.rotate_root') as mock_rotate:
        for _ in range(6):
            run_next_step(job)
    return mock_e13, mock_add, mock_rotate


class TestCardBlock:

    def test_shown_for_connected_server(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert f'/servers/{server.id}/new-machine' in page

    def test_hidden_for_unconnected_server(self, admin_client, db, default_group):
        server = _make_server(db, default_group, vps_id=None)
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert '/new-machine' not in page

    def test_hidden_while_provisioning(self, admin_client, db, default_group):
        server = _make_server(db, default_group, status='provisioning')
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert '/new-machine' not in page


class TestEndpoint:

    def test_starts_job_with_typed_password_and_target_address(
            self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        resp = admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()
        assert resp.headers['Location'].endswith(f'/provisioning/jobs/{job.id}')

        state = _state(job)
        assert decrypt(state['bootstrap_cred']) == 'Hoster-New-1'
        assert state['new_machine'] == {'ip_address': '198.51.100.7', 'ssh_port': 22}
        db.session.refresh(server)
        # Адрес меняется только после успеха E13.
        assert (server.ip_address, server.ssh_port) == ('192.0.2.60', 2233)
        assert server.provisioning_status == 'provisioning'
        assert server.bootstrap_request_id == 'old-request-id'

    @pytest.mark.parametrize('override, message', [
        ({'ip_address': 'not-an-ip'}, 'Некорректный IP-адрес'),
        ({'ip_address': ''}, 'Некорректный IP-адрес'),
        ({'ip_address': 'fe80::1%eth0'}, 'Некорректный IP-адрес'),
        ({'ssh_port': '0'}, 'Порт должен быть'),
        ({'ssh_port': 'abc'}, 'Порт должен быть'),
        ({'ssh_port': '65536'}, 'Порт должен быть'),
        ({'password': ''}, 'Введите пароль root'),
        ({'password': '   '}, 'Введите пароль root'),
    ])
    def test_invalid_form_rejected(self, admin_client, db, default_group, override, message):
        server = _make_server(db, default_group)
        resp = admin_client.post(f'/servers/{server.id}/new-machine', data={**FORM, **override})
        assert resp.headers['Location'].endswith(f'/servers/{server.id}')
        assert ProvisioningJob.query.count() == 0
        assert message in admin_client.get(f'/servers/{server.id}').data.decode()

    def test_unconnected_server_rejected(self, admin_client, db, default_group):
        server = _make_server(db, default_group, vps_id=None)
        admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        assert ProvisioningJob.query.count() == 0

    def test_active_job_blocks_second_run(self, admin_client, db, default_group, admin_user):
        server = _make_server(db, default_group)
        start_new_machine(server, admin_user, 'first', '198.51.100.7', 22)
        server.provisioning_status = 'ready'  # блок виден, job ещё активен
        db.session.commit()
        admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        assert ProvisioningJob.query.filter_by(server_id=server.id).count() == 1

    def test_already_provisioning_is_not_claimed_twice(self, db, default_group, admin_user):
        from app.services.provisioning import OnboardingLockedError
        server = _make_server(db, default_group, status='provisioning')
        with pytest.raises(OnboardingLockedError):
            start_new_machine(server, admin_user, 'pw', '198.51.100.7', 22)
        assert ProvisioningJob.query.count() == 0

    def test_foreign_server_forbidden(self, admin_client, db):
        from app.models import ServerGroup
        other = ServerGroup(name='other-group')
        db.session.add(other)
        db.session.commit()
        server = _make_server(db, other)
        resp = admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        assert resp.status_code == 403
        assert ProvisioningJob.query.count() == 0


class TestPipeline:

    def test_success_moves_address_rotates_password_and_reports_redeploy(
            self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()

        mock_e13, mock_add, mock_rotate = _run_all(job, E13_OK)

        mock_add.assert_not_called()
        args, kwargs = mock_e13.call_args
        assert args == (42,)
        assert kwargs == {'ip_address': '198.51.100.7', 'ssh_port': 22,
                          'username': 'root', 'password': 'Hoster-New-1'}
        # Ротация идёт уже на новую машину.
        assert mock_rotate.call_args.kwargs['host'] == '198.51.100.7'
        assert mock_rotate.call_args.kwargs['port'] == 22

        db.session.refresh(server)
        assert (server.ip_address, server.ssh_port) == ('198.51.100.7', 22)
        assert server.vps_manager_server_id == 42
        assert server.provisioning_status == 'ready'
        assert server.password not in (None, 'Old-Machine-Root', 'Hoster-New-1')
        db.session.refresh(job)
        assert job.status == 'success'
        assert 'bootstrap_cred' not in _state(job)

        page = admin_client.get(f'/provisioning/jobs/{job.id}').data.decode()
        assert 'новая машина подключена' in page
        assert 'докатано 1 из 2' in page
        assert 'alice' in page and 'disk full' in page
        assert 'текущий пароль root из карточки' in page

    def test_e13_failure_keeps_address_and_restart_retries_same_target(
            self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()

        _run_all(job, {'success': False, 'message': 'Authentication failed'})
        db.session.refresh(server)
        db.session.refresh(job)
        assert job.status == 'failed'
        assert server.provisioning_status == 'provisioning_failed'
        assert (server.ip_address, server.ssh_port) == ('192.0.2.60', 2233)
        assert server.password == 'Old-Machine-Root'
        # Карточка подключённого сервера показывает ошибку и Restart.
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert 'Authentication failed' in page
        assert f'/provisioning/jobs/{job.id}/restart' in page

        restart_job(job)
        mock_e13, _, _ = _run_all(job, E13_OK)
        assert mock_e13.call_args.kwargs['ip_address'] == '198.51.100.7'
        assert mock_e13.call_args.kwargs['password'] == 'Hoster-New-1'
        db.session.refresh(server)
        assert (server.ip_address, server.provisioning_status) == ('198.51.100.7', 'ready')

    def test_root_is_used_whatever_card_username(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        server.ssh_username = 'ubuntu'
        db.session.commit()
        admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()
        mock_e13, _, _ = _run_all(job, E13_OK)
        assert mock_e13.call_args.kwargs['username'] == 'root'

    def test_restart_of_older_job_is_refused(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        old = ProvisioningJob.query.filter_by(server_id=server.id).one()
        _run_all(old, {'success': False, 'message': 'Authentication failed'})
        admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        new = ProvisioningJob.query.filter(ProvisioningJob.id != old.id).one()

        resp = admin_client.post(f'/provisioning/jobs/{old.id}/restart')
        assert resp.headers['Location'].endswith(f'/servers/{server.id}')
        db.session.refresh(old)
        assert old.status == 'failed'
        assert 'более новое задание' in admin_client.get(f'/servers/{server.id}').data.decode()
        # Последнее задание перезапускать можно.
        resp = admin_client.post(f'/provisioning/jobs/{new.id}/restart')
        assert resp.headers['Location'].endswith(f'/provisioning/jobs/{new.id}')

    def test_job_page_without_redeploy_failures(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        admin_client.post(f'/servers/{server.id}/new-machine', data=FORM)
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()
        _run_all(job, {**E13_OK, 'redeploy': {'total': 3, 'deployed': 3, 'failed': []}})
        page = admin_client.get(f'/provisioning/jobs/{job.id}').data.decode()
        assert 'докатано 3 из 3' in page
        assert 'текущий пароль root из карточки' not in page

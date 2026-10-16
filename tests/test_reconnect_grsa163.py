"""GRSA-163, ветка 1: подключение к VPS Manager из карточки сервера.

Мокаем app.services.provisioning.vps_client — реального VPS Manager нет.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from flask_sqlalchemy.query import Query

from app.models import ProvisioningJob, Server, User
from app.security import decrypt
from app.services.provisioning import (
    OnboardingLockedError,
    run_next_step,
    start_onboarding,
)


def _make_server(db, group, name='vps-reconnect-01', password='Stored-Root-1',
                 vps_id=None, status='ready', request_id='old-request-id'):
    server = Server(name=name, ip_address='192.0.2.60', ssh_username='root',
                    ssh_port=2233, active=True, group_id=group.id,
                    vps_manager_server_id=vps_id, provisioning_status=status,
                    bootstrap_request_id=request_id)
    server.password = password
    db.session.add(server)
    db.session.commit()
    return server


def _cred(job):
    return decrypt(json.loads(job.steps_json)['bootstrap_cred'])


class TestReconnectButton:

    def test_shown_for_unconnected_server(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert f'/servers/{server.id}/reconnect' in page

    def test_shown_for_failed_without_job(self, admin_client, db, default_group):
        server = _make_server(db, default_group, status='provisioning_failed')
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert f'/servers/{server.id}/reconnect' in page

    def test_quote_in_name_does_not_break_confirm(self, admin_client, db, default_group):
        server = _make_server(db, default_group, name="x');alert(1);//")
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        line = next(l for l in page.splitlines() if "onsubmit='return confirm(" in l)
        # Атрибут в одинарных кавычках, строка JS — JSON: кавычка имени экранирована
        # как \u0027 и не закрывает ни атрибут, ни строку.
        assert 'x\\u0027);alert(1);//' in line, line
        assert "x');" not in line, line

    def test_hidden_for_connected_server(self, admin_client, db, default_group):
        server = _make_server(db, default_group, vps_id=42)
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert '/reconnect' not in page

    def test_hidden_while_provisioning(self, admin_client, db, default_group):
        server = _make_server(db, default_group, status='provisioning')
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert '/reconnect' not in page


class TestReconnectEndpoint:

    def test_empty_password_uses_stored_one(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        resp = admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ''})

        job = ProvisioningJob.query.filter_by(server_id=server.id).one()
        assert resp.status_code == 302
        assert resp.headers['Location'].endswith(f'/provisioning/jobs/{job.id}')
        assert _cred(job) == 'Stored-Root-1'
        db.session.refresh(server)
        assert server.provisioning_status == 'provisioning'
        # Прежний id сохраняется: VPS Manager запоминает его только при успехе,
        # и если прошлый успех потерялся по таймауту, тот же id вернёт его без дубля.
        assert server.bootstrap_request_id == 'old-request-id'

    def test_typed_password_overrides_stored(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        # Без strip: как и форма создания, пароль хостера передаётся как введён.
        admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ' Typed-Pw-2 '})
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()
        assert _cred(job) == ' Typed-Pw-2 '

    def test_connected_server_rejected(self, admin_client, db, default_group):
        server = _make_server(db, default_group, vps_id=42)
        resp = admin_client.post(f'/servers/{server.id}/reconnect', data={'password': 'x'})
        assert resp.status_code == 302
        assert resp.headers['Location'].endswith(f'/servers/{server.id}')
        assert ProvisioningJob.query.count() == 0
        db.session.refresh(server)
        assert server.bootstrap_request_id == 'old-request-id'

    def test_no_password_anywhere_rejected(self, admin_client, db, default_group):
        server = _make_server(db, default_group, password=None)
        resp = admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ''})
        assert resp.headers['Location'].endswith(f'/servers/{server.id}')
        assert ProvisioningJob.query.count() == 0
        page = admin_client.get(f'/servers/{server.id}').data.decode()
        assert 'Пароля root нет' in page

    def test_active_job_blocks_second_run(self, admin_client, db, default_group, admin_user):
        server = _make_server(db, default_group, status='provisioning_failed')
        start_onboarding(server, admin_user, 'first')
        server.provisioning_status = 'provisioning_failed'  # кнопка видна, job ещё активен
        db.session.commit()
        resp = admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ''})
        assert resp.headers['Location'].endswith(f'/servers/{server.id}')
        assert ProvisioningJob.query.filter_by(server_id=server.id).count() == 1

    def test_foreign_server_forbidden(self, admin_client, db):
        from app.models import ServerGroup
        other = ServerGroup(name='other-group')
        db.session.add(other)
        db.session.commit()
        server = _make_server(db, other)
        resp = admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ''})
        assert resp.status_code == 403
        assert ProvisioningJob.query.count() == 0

    def test_bootstrap_gets_stored_password_and_connects(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ''})
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {'success': True, 'server_id': 901}
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap

        kwargs = mock_add.call_args.kwargs
        assert kwargs['password'] == 'Stored-Root-1'
        assert kwargs['ssh_port'] == 2233
        db.session.refresh(server)
        assert server.vps_manager_server_id == 901

    def test_whitespace_password_falls_back_to_stored(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        admin_client.post(f'/servers/{server.id}/reconnect', data={'password': '   '})
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()
        assert _cred(job) == 'Stored-Root-1'

    def test_typed_password_used_when_none_stored(self, admin_client, db, default_group):
        server = _make_server(db, default_group, password=None)
        admin_client.post(f'/servers/{server.id}/reconnect', data={'password': 'Typed-Only'})
        job = ProvisioningJob.query.filter_by(server_id=server.id).one()
        assert _cred(job) == 'Typed-Only'

    @pytest.mark.parametrize('empty', [None, ''])
    def test_empty_request_id_gets_generated(self, admin_client, db, default_group, empty):
        server = _make_server(db, default_group, request_id=empty)
        admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ''})
        db.session.refresh(server)
        assert server.bootstrap_request_id and len(server.bootstrap_request_id) == 32

    def test_retry_after_failed_job_creates_new_job(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ''})
        first = ProvisioningJob.query.filter_by(server_id=server.id).one()
        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {'success': False, 'message': 'unreachable'}
            run_next_step(first)  # catalog
            run_next_step(first)  # bootstrap -> failed
        db.session.refresh(server)
        assert server.provisioning_status == 'provisioning_failed'

        resp = admin_client.post(f'/servers/{server.id}/reconnect', data={'password': ''})
        jobs = ProvisioningJob.query.filter_by(server_id=server.id).order_by(ProvisioningJob.id).all()
        assert len(jobs) == 2
        assert resp.headers['Location'].endswith(f'/provisioning/jobs/{jobs[1].id}')


class TestConcurrentReconnect:
    """Два запроса, перекрывшихся между проверкой активного job'а и его созданием.

    Сценарий из финального ревью: B проходит pipeline до bootstrap, пока A стоит
    после своей проверки. Без атомарного захвата A заводил второй job с другим
    bootstrap_request_id, и VPS Manager создавал дубль.
    """

    def test_second_concurrent_start_is_rejected(self, app, db, admin_user, default_group):
        server = _make_server(db, default_group, request_id=None)
        sid, uid = server.id, admin_user.id
        original_first = Query.first
        paused = False
        remote_ids = []

        def remote_add(**kwargs):
            remote_ids.append(kwargs['bootstrap_request_id'])
            return {'success': True, 'server_id': 100 + len(remote_ids)}

        def interleave(query):
            nonlocal paused
            result = original_first(query)
            if not paused:
                paused = True
                assert result is None  # A прошёл проверку активного job'а
                with app.app_context():  # B — отдельная сессия
                    other = db.session.get(Server, sid)
                    job_b = start_onboarding(other, db.session.get(User, uid), 'pw')
                    run_next_step(job_b)  # catalog
                    run_next_step(job_b)  # bootstrap
            return result

        with patch.object(Query, 'first', interleave), patch(
                'app.services.provisioning.vps_client.add_server', side_effect=remote_add), \
                pytest.raises(OnboardingLockedError):
            start_onboarding(server, admin_user, 'pw')

        assert ProvisioningJob.query.filter_by(server_id=sid).count() == 1
        assert len(remote_ids) == 1
        db.session.refresh(server)
        assert server.vps_manager_server_id == 101
        assert server.bootstrap_request_id == remote_ids[0]

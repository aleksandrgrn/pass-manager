"""Track C A3.1: каталог + bootstrap (шаги 1-2 pipeline онбординга).

Мокаем app.services.provisioning.vps_client — реального VPS Manager нет.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from app.extensions import db
from app.models import ProvisioningJob, Server, User
from app.services.provisioning import (
    STEPS, OnboardingLockedError, restart_job, run_next_step, start_onboarding,
)
from app.services.rotate import RotateError


def _make_server(db, name='vps-onboard-01', ip='192.0.2.50', group=None):
    """group нужен только тестам, которые ходят по HTTP: с B1 admin видит
    сервер, лишь если тот в его группе. Тесты сервисного слоя обходятся без него."""
    server = Server(name=name, ip_address=ip, ssh_username='root', active=True,
                    group_id=group.id if group else None)
    db.session.add(server)
    db.session.commit()
    return server


def _make_user(db, username='onboard-user'):
    user = User(username=username, role='admin', is_local=True)
    db.session.add(user)
    db.session.commit()
    return user


# --------------------------------------------------------------------------- #
# Р4: онбординг — опция, ручное добавление не ломается
# --------------------------------------------------------------------------- #

class TestOnboardingAlwaysRuns:
    """Онбординг запускается при каждом заведении сервера."""

    def test_create_with_onboarding_creates_job(self, admin_client, db):
        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {'success': True, 'server_id': 555}
            resp = admin_client.post('/servers/new', data={
                'name': 'vps-auto-01',
                'ip_address': '198.51.100.70',
                'password': 'Init-Pass-123!',
            })

        # PRG: онбординг редиректит на страницу job'а. Отрисовка страницы прямо
        # в ответ на POST оставляла в истории браузера запись, уже создавшую
        # сервер — F5 плюс «повторить» заводил второй сервер (имя не уникально)
        # и второй pipeline по живой машине.
        assert resp.status_code == 302

        server = Server.query.filter_by(name='vps-auto-01').first()
        assert server is not None
        assert server.provisioning_status == 'provisioning'
        assert server.bootstrap_request_id

        job = ProvisioningJob.query.filter_by(server_id=server.id).first()
        assert job is not None
        assert resp.headers['Location'].endswith(f'/provisioning/jobs/{job.id}')
        assert job.job_type == 'onboarding'
        assert job.status == 'running'
        # Первый шаг (catalog) ещё не запущен вручную -> vps_client не звался
        # на этапе создания записи (звонок происходит только в шаге bootstrap).
        mock_add.assert_not_called()


class TestOnboardingHasNoOptOut:
    """Галки больше нет: онбординг обязателен, и без пароля форма не проходит.

    Отказаться от онбординга нельзя — иначе сервер заводится не подключённым к
    VPS Manager, а подключить его потом нечем: start_onboarding вызывается
    только из формы создания.
    """

    def test_create_page_has_no_onboarding_checkbox(self, admin_client, db):
        resp = admin_client.get('/servers/new')
        assert resp.status_code == 200
        assert b'do_onboarding' not in resp.data
        assert b'bootstrap_password' not in resp.data

    def test_onboarding_without_password_rejected(self, admin_client, db):
        resp = admin_client.post('/servers/new', data={
            'name': 'vps-no-pw-01',
            'ip_address': '198.51.100.71',
        })

        assert resp.status_code == 200  # форма перерисована с ошибкой
        assert Server.query.filter_by(name='vps-no-pw-01').first() is None
        assert ProvisioningJob.query.count() == 0


# --------------------------------------------------------------------------- #
# Шаг bootstrap: успех / ошибка / идемпотентность / утечка пароля
# --------------------------------------------------------------------------- #

class TestBootstrapStep:

    def test_bootstrap_success_stores_id_and_clears_cred(self, app, db):
        user = _make_user(db)
        server = _make_server(db)
        job = start_onboarding(server, user, 'S3cret-Boot-Pw')

        # Сразу после start_onboarding bootstrap_cred присутствует (Р1).
        state = json.loads(job.steps_json)
        assert 'bootstrap_cred' in state

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {'success': True, 'server_id': 777}
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap

        db.session.refresh(server)
        db.session.refresh(job)

        assert server.vps_manager_server_id == 777
        state = json.loads(job.steps_json)
        assert state['steps']['bootstrap'] == 'done'
        assert 'bootstrap_cred' not in state  # стёрт сразу после успеха (Р1)

    def test_bootstrap_failure_marks_job_and_server_failed(self, app, db):
        user = _make_user(db, 'u-fail')
        server = _make_server(db, name='vps-fail-01')
        job = start_onboarding(server, user, 'pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {
                'success': False, 'error_type': 'connection_refused', 'message': 'boom',
            }
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap -> fails

        db.session.refresh(server)
        db.session.refresh(job)

        assert job.status == 'failed'
        assert server.provisioning_status == 'provisioning_failed'
        assert job.error_message

    def test_bootstrap_not_called_twice(self, app, db, tmp_path):
        """Повторный вызов run_next_step после успеха не дёргает vps_client снова."""
        app.config['ANSIBLE_KEYS_DIR'] = str(tmp_path)  # A3.2: fetch_key пишет сюда
        user = _make_user(db, 'u-idem')
        server = _make_server(db, name='vps-idem-01')
        job = start_onboarding(server, user, 'pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add, \
                patch('app.services.provisioning.vps_client.get_access_key') as mock_key:
            mock_add.return_value = {'success': True, 'server_id': 42}
            mock_key.return_value = {'success': True, 'private_key': 'PEM'}
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap
            run_next_step(job)  # fetch_key — не должен снова звать add_server

            assert mock_add.call_count == 1

    def test_job_becomes_terminal_when_all_steps_done(self, app, db, tmp_path):
        """Пройдя все шаги, job обязан стать терминальным.

        Иначе modal никогда не остановит HTMX-поллинг (условие остановки в
        шаблоне смотрит на job.status) — бесконечный цикл запросов.
        """
        app.config['ANSIBLE_KEYS_DIR'] = str(tmp_path)  # A3.2: fetch_key пишет сюда
        user = _make_user(db, 'u-terminal')
        server = _make_server(db, name='vps-terminal-01')
        job = start_onboarding(server, user, 'pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add, \
                patch('app.services.provisioning.vps_client.get_access_key') as mock_key, \
                patch('app.services.provisioning.rotate_root') as mock_rotate:
            mock_add.return_value = {'success': True, 'server_id': 9}
            mock_key.return_value = {'success': True, 'private_key': 'PEM'}
            for _ in range(len(STEPS) + 2):  # с запасом: лишние вызовы — no-op
                run_next_step(job)

        db.session.refresh(job)
        assert job.status == 'success'
        assert job.finished_at is not None
        mock_rotate.assert_called_once()

    def test_custom_ssh_port_passed_to_vps_manager(self, app, db):
        """Порт берётся из сервера, а не зашит в 22 (в парке есть хосты на 2233)."""
        user = _make_user(db, 'u-port')
        server = _make_server(db, name='vps-port-01')
        server.ssh_port = 2233
        db.session.commit()
        job = start_onboarding(server, user, 'pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {'success': True, 'server_id': 11}
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap

        assert mock_add.call_args.kwargs['ssh_port'] == 2233

    def test_missing_ssh_port_falls_back_to_22(self, app, db):
        user = _make_user(db, 'u-port-default')
        server = _make_server(db, name='vps-port-02')  # ssh_port не задан
        job = start_onboarding(server, user, 'pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {'success': True, 'server_id': 12}
            run_next_step(job)
            run_next_step(job)

        assert mock_add.call_args.kwargs['ssh_port'] == 22

    def test_bootstrap_password_not_leaked(self, app, db):
        """bootstrap_password не оседает ни в Server.password, ни в открытом виде в steps_json."""
        user = _make_user(db, 'u-secret')
        server = _make_server(db, name='vps-secret-01')
        job = start_onboarding(server, user, 'top-secret-pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {'success': True, 'server_id': 1}
            run_next_step(job)
            run_next_step(job)

        db.session.refresh(server)
        db.session.refresh(job)

        assert server.password is None
        state = json.loads(job.steps_json)
        assert 'bootstrap_cred' not in state


# --------------------------------------------------------------------------- #
# A3.2: шаг fetch_key — забрать per-server root-ключ на ФС
# --------------------------------------------------------------------------- #

class TestFetchKeyStep:

    def test_fetch_key_success_writes_file_with_0600(self, app, db, tmp_path):
        app.config['ANSIBLE_KEYS_DIR'] = str(tmp_path)
        user = _make_user(db, 'u-fetch')
        server = _make_server(db, name='vps-fetch-01')
        job = start_onboarding(server, user, 'pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add, \
                patch('app.services.provisioning.vps_client.get_access_key') as mock_key:
            mock_add.return_value = {'success': True, 'server_id': 900}
            mock_key.return_value = {'success': True, 'private_key': 'PEM-DATA'}
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap
            run_next_step(job)  # fetch_key

        key_file = tmp_path / f'{server.id}_root.pem'
        assert key_file.read_text() == 'PEM-DATA'
        assert oct(key_file.stat().st_mode & 0o777) == '0o600'

    def test_fetch_key_failure_marks_provisioning_failed(self, app, db, tmp_path):
        app.config['ANSIBLE_KEYS_DIR'] = str(tmp_path)
        user = _make_user(db, 'u-fetch-fail')
        server = _make_server(db, name='vps-fetch-fail-01')
        job = start_onboarding(server, user, 'pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add, \
                patch('app.services.provisioning.vps_client.get_access_key') as mock_key:
            mock_add.return_value = {'success': True, 'server_id': 901}
            mock_key.return_value = {'success': False, 'message': 'not found'}
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap
            run_next_step(job)  # fetch_key -> fails

        db.session.refresh(server)
        db.session.refresh(job)

        assert job.status == 'failed'
        assert server.provisioning_status == 'provisioning_failed'
        assert 'key_fetch_failed' in job.error_message


def _run_to_rotate(app, db, tmp_path, server_name):
    """Доводит job до шага rotate (catalog+bootstrap+fetch_key уже пройдены)."""
    app.config['ANSIBLE_KEYS_DIR'] = str(tmp_path)
    user = _make_user(db, f'u-{server_name}')
    server = _make_server(db, name=server_name)
    job = start_onboarding(server, user, 'pw')
    with patch('app.services.provisioning.vps_client.add_server') as mock_add, \
            patch('app.services.provisioning.vps_client.get_access_key') as mock_key:
        mock_add.return_value = {'success': True, 'server_id': 1000}
        mock_key.return_value = {'success': True, 'private_key': 'PEM'}
        run_next_step(job)  # catalog
        run_next_step(job)  # bootstrap
        run_next_step(job)  # fetch_key
    return server, job


# --------------------------------------------------------------------------- #
# A3.2: шаг rotate — write-ahead, retry, promote
# --------------------------------------------------------------------------- #

class TestRotateStep:

    def test_write_ahead_rotate_failure_keeps_password_pending(self, app, db, tmp_path):
        """Главный тест среза: rotate_root падает -> password_pending заполнен,
        Server.password не изменён (страховка, loss-window = 0)."""
        server, job = _run_to_rotate(app, db, tmp_path, 'vps-rotate-fail-01')

        with patch('app.services.provisioning.rotate_root', side_effect=RotateError('ssh boom')):
            run_next_step(job)  # rotate -> исключение

        db.session.refresh(server)
        db.session.refresh(job)

        assert server.password_pending is not None  # страховка осталась в БД
        assert server.password is None  # promote не наступил
        assert job.status == 'failed'
        assert server.provisioning_status == 'provisioning_failed'

    def test_successful_rotate_and_promote_sets_password(self, app, db, tmp_path):
        server, job = _run_to_rotate(app, db, tmp_path, 'vps-rotate-ok-01')

        with patch('app.services.provisioning.rotate_root') as mock_rotate:
            run_next_step(job)  # rotate
            db.session.refresh(server)
            pending = server.password_pending
            assert pending is not None
            run_next_step(job)  # promote

        db.session.refresh(server)
        db.session.refresh(job)

        assert server.password == pending
        assert server.password_pending is None
        assert server.provisioning_status == 'ready'
        assert job.status == 'success'
        mock_rotate.assert_called_once()

    def test_retry_reuses_existing_password_pending(self, app, db, tmp_path):
        """Retry шага rotate не генерирует новый пароль, если password_pending уже есть."""
        server, job = _run_to_rotate(app, db, tmp_path, 'vps-rotate-retry-01')

        with patch('app.services.provisioning.rotate_root', side_effect=RotateError('boom')):
            run_next_step(job)  # rotate падает, password_pending выставлен

        db.session.refresh(server)
        first_pending = server.password_pending
        assert first_pending is not None

        # "Реанимируем" job для повторной попытки шага rotate (в реальности —
        # кнопка Restart из A3.3; здесь просто возвращаем шаг в pending).
        job.status = 'running'
        state = json.loads(job.steps_json)
        state['steps']['rotate'] = 'pending'
        job.steps_json = json.dumps(state)
        db.session.commit()

        with patch('app.services.provisioning.rotate_root') as mock_rotate:
            run_next_step(job)  # rotate retry -> успех

        db.session.refresh(server)
        assert server.password_pending == first_pending  # пароль не перегенерирован
        assert mock_rotate.call_args.kwargs['new_password'] == first_pending


# --------------------------------------------------------------------------- #
# Редактирование сервера: онбординг там не запускается
# --------------------------------------------------------------------------- #

class TestEditDoesNotOnboard:

    def test_edit_page_has_no_onboarding_block(self, admin_client, db, default_group):
        server = _make_server(db, name='vps-edit-01', ip='198.51.100.80', group=default_group)
        resp = admin_client.get(f'/servers/{server.id}/edit')
        assert resp.status_code == 200
        assert b'do_onboarding' not in resp.data

    def test_edit_does_not_create_job_or_leak_transient_fields(self, admin_client, db, default_group):
        server = _make_server(db, name='vps-edit-02', ip='198.51.100.81', group=default_group)
        resp = admin_client.post(f'/servers/{server.id}/edit', data={
            'name': 'vps-edit-02-renamed',
            'ip_address': '198.51.100.81',
            # Транзиентные поля подсунуты вручную — не должны попасть в модель.
            'do_onboarding': 'y',
            'bootstrap_password': 'should-be-ignored',
        })
        assert resp.status_code == 302

        db.session.refresh(server)
        assert server.name == 'vps-edit-02-renamed'
        assert ProvisioningJob.query.count() == 0
        assert not hasattr(server, 'bootstrap_password')
        assert server.password is None


# --------------------------------------------------------------------------- #
# A3.3: app-lock — один активный job на сервер (FIX-6c)
# --------------------------------------------------------------------------- #

class TestAppLock:

    def test_second_onboarding_for_same_server_rejected(self, app, db):
        user = _make_user(db, 'u-lock')
        server = _make_server(db, name='vps-lock-01')
        start_onboarding(server, user, 'pw-1')

        assert ProvisioningJob.query.filter_by(server_id=server.id).count() == 1
        with pytest.raises(OnboardingLockedError):
            start_onboarding(server, user, 'pw-2')
        # Повторная попытка не создала второй job.
        assert ProvisioningJob.query.filter_by(server_id=server.id).count() == 1

    def test_onboarding_allowed_after_job_terminal(self, app, db, tmp_path):
        """Лок снимается, когда предыдущий job дошёл до терминального статуса."""
        app.config['ANSIBLE_KEYS_DIR'] = str(tmp_path)
        user = _make_user(db, 'u-lock-2')
        server = _make_server(db, name='vps-lock-02')
        job = start_onboarding(server, user, 'pw-1')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {
                'success': False, 'message': 'boom',
            }
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap -> failed, job терминален

        db.session.refresh(job)
        assert job.status == 'failed'

        # Второй онбординг того же сервера теперь разрешён (старый job не активен).
        job2 = start_onboarding(server, user, 'pw-2')
        assert job2.id != job.id


# --------------------------------------------------------------------------- #
# A3.3: гонка двух одновременных поллингов внутри run_next_step (FIX-6c)
# --------------------------------------------------------------------------- #

class TestConcurrentPollGuard:

    def test_step_marked_running_is_not_executed_twice(self, app, db):
        """Симулирует гонку: шаг уже помечен 'running' другим поллингом —
        повторный вход в run_next_step не должен снова дёргать vps_client."""
        user = _make_user(db, 'u-race')
        server = _make_server(db, name='vps-race-01')
        job = start_onboarding(server, user, 'pw')
        run_next_step(job)  # catalog -> done

        state = json.loads(job.steps_json)
        state['steps']['bootstrap'] = 'running'
        job.steps_json = json.dumps(state)
        db.session.commit()

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            result = run_next_step(job)

        mock_add.assert_not_called()
        assert result['bootstrap'] == 'running'  # шаг не тронут повторным входом

    def test_running_step_leaves_running_after_execution(self, app, db, tmp_path):
        """После выполнения шаг обязан покинуть 'running' — иначе pipeline
        встанет намертво (следующий поллинг будет видеть 'running' вечно)."""
        app.config['ANSIBLE_KEYS_DIR'] = str(tmp_path)
        user = _make_user(db, 'u-race-2')
        server = _make_server(db, name='vps-race-02')
        job = start_onboarding(server, user, 'pw')

        with patch('app.services.provisioning.vps_client.add_server') as mock_add:
            mock_add.return_value = {'success': True, 'server_id': 321}
            run_next_step(job)  # catalog
            run_next_step(job)  # bootstrap

        state = json.loads(job.steps_json)
        assert state['steps']['bootstrap'] == 'done'  # не осталось 'running'


# --------------------------------------------------------------------------- #
# A3.3: Restart pipeline — продолжает с упавшего шага
# --------------------------------------------------------------------------- #

class TestRestartPipeline:

    def test_restart_unsticks_step_left_running_by_dead_worker(self, app, db, tmp_path):
        """Воркер умер между коммитом 'running' и коммитом результата.

        Шаг залипает в 'running': поллинг видит его и выходит без исполнения,
        job навсегда не завершён, а сервер — в 'provisioning'. Restart обязан
        вытащить pipeline из этого состояния (шаги идемпотентны).
        """
        server, job = _run_to_rotate(app, db, tmp_path, 'vps-stuck-01')

        # Симулируем смерть воркера: шаг закоммичен как 'running' и брошен.
        state = json.loads(job.steps_json)
        state['steps']['rotate'] = 'running'
        job.steps_json = json.dumps(state)
        db.session.commit()

        # Сам по себе поллинг pipeline не сдвинет — шаг считается исполняемым.
        with patch('app.services.provisioning.rotate_root') as mock_rotate:
            run_next_step(job)
            mock_rotate.assert_not_called()

        restart_job(job)

        with patch('app.services.provisioning.rotate_root') as mock_rotate:
            run_next_step(job)   # rotate
            run_next_step(job)   # promote
            mock_rotate.assert_called_once()

        db.session.refresh(job)
        db.session.refresh(server)
        assert job.status == 'success'
        assert server.provisioning_status == 'ready'

    def test_restart_resumes_from_failed_step_without_rerunning_success(
        self, app, db, tmp_path,
    ):
        server, job = _run_to_rotate(app, db, tmp_path, 'vps-restart-01')

        with patch('app.services.provisioning.rotate_root', side_effect=RotateError('boom')):
            run_next_step(job)  # rotate -> failed

        db.session.refresh(job)
        db.session.refresh(server)
        assert job.status == 'failed'
        assert server.provisioning_status == 'provisioning_failed'

        restart_job(job)

        db.session.refresh(job)
        db.session.refresh(server)
        assert job.status == 'running'
        assert job.error_message is None
        assert server.provisioning_status == 'provisioning'

        state = json.loads(job.steps_json)
        assert state['steps']['rotate'] == 'pending'
        # Успешные шаги (catalog/bootstrap/fetch_key) restart не трогает.
        assert state['steps']['catalog'] == 'done'
        assert state['steps']['bootstrap'] == 'done'
        assert state['steps']['fetch_key'] == 'done'

        with patch('app.services.provisioning.vps_client.add_server') as mock_add, \
                patch('app.services.provisioning.vps_client.get_access_key') as mock_key, \
                patch('app.services.provisioning.rotate_root') as mock_rotate:
            run_next_step(job)  # rotate retry -> успех
            run_next_step(job)  # promote

        mock_add.assert_not_called()   # bootstrap не перезапущен
        mock_key.assert_not_called()   # fetch_key не перезапущен
        mock_rotate.assert_called_once()

        db.session.refresh(job)
        db.session.refresh(server)
        assert job.status == 'success'
        assert server.provisioning_status == 'ready'


# --------------------------------------------------------------------------- #
# A3.3: UI — статус в detail.html, HTTP-проход через endpoint restart
# --------------------------------------------------------------------------- #

def _make_failed_job(db, server, user, failed_step='rotate'):
    steps = {s: 'done' for s in STEPS}
    idx = STEPS.index(failed_step)
    steps[failed_step] = 'failed'
    for s in STEPS[idx + 1:]:
        steps[s] = 'pending'
    job = ProvisioningJob(
        server_id=server.id, initiated_by=user.id, job_type='onboarding',
        status='failed', error_message=f'{failed_step}_failed: boom',
        steps_json=json.dumps({'steps': steps}),
    )
    db.session.add(job)
    server.provisioning_status = 'provisioning_failed'
    db.session.commit()
    return job


class TestProvisioningFailedUI:

    def test_detail_shows_error_and_restart_button(self, admin_client, db, default_group):
        user = _make_user(db, 'u-ui')
        server = _make_server(db, name='vps-ui-01', group=default_group)
        job = _make_failed_job(db, server, user)

        resp = admin_client.get(f'/servers/{server.id}')

        assert resp.status_code == 200
        assert b'provisioning_failed' in resp.data
        assert b'rotate_failed: boom' in resp.data
        assert f'/provisioning/jobs/{job.id}/restart'.encode() in resp.data

    def test_restart_endpoint_resumes_pipeline(self, admin_client, db, tmp_path, app, default_group):
        app.config['ANSIBLE_KEYS_DIR'] = str(tmp_path)
        user = _make_user(db, 'u-ui-2')
        server = _make_server(db, name='vps-ui-02', group=default_group)
        job = _make_failed_job(db, server, user)

        resp = admin_client.post(f'/provisioning/jobs/{job.id}/restart')

        # PRG: restart тоже редиректит — иначе F5 перезапускал pipeline
        # по живой машине.
        assert resp.status_code == 302
        assert resp.headers['Location'].endswith(f'/provisioning/jobs/{job.id}')
        assert b'provisioning-steps' in admin_client.get(
            f'/provisioning/jobs/{job.id}').data

        db.session.refresh(job)
        db.session.refresh(server)
        assert job.status == 'running'
        assert server.provisioning_status == 'provisioning'
        state = json.loads(job.steps_json)
        assert state['steps']['rotate'] == 'pending'

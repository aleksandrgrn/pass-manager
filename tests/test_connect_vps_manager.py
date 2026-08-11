"""Track C FIX-C1-1: тесты скрипта подключения серверов к VPS Manager.

Фикстуры — из tests/conftest.py (app, db), мокаем по образцу
test_provisioning_a3.py: patch('scripts.connect_to_vps_manager.vps_client.add_server').
Живых вызовов нет ни одного.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.models import Server
from scripts.connect_to_vps_manager import (
    CAT_ALREADY,
    CAT_BAD_USER,
    CAT_CONNECTED,
    CAT_DRY_RUN,
    CAT_DUPLICATE,
    CAT_ERROR,
    CAT_FAILED,
    CAT_NO_ADDR,
    CAT_NO_PASSWORD,
    CAT_NO_SERVER,
    CAT_UNREACHABLE,
    connect_servers,
    report_and_check,
)


def _make_server(db, name='vps-c1-01', password=None, **kwargs):
    """Сервер с адресом и ssh_username='root' по умолчанию; password задаётся явно."""
    defaults = {'name': name, 'ip_address': '192.0.2.10', 'ssh_username': 'root'}
    defaults.update(kwargs)
    server = Server(**defaults)
    if password is not None:
        server.password = password  # hybrid-setter: прозрачно, dev no-op режим
    db.session.add(server)
    db.session.commit()
    return server


def _run(server_ids, ret=None, port=2233, dry_run=False):
    """Вызвать connect_servers с опциональным возвратом мока add_server."""
    with patch('scripts.connect_to_vps_manager.vps_client.add_server') as mock_add:
        if ret is not None:
            mock_add.return_value = ret
        categories = connect_servers(server_ids, port=port, dry_run=dry_run)
    return categories, mock_add


# --------------------------------------------------------------------------- #
# 1. Успех пишет vps_manager_server_id и ssh_port
# --------------------------------------------------------------------------- #

class TestSuccess:

    def test_success_writes_id_and_port(self, app, db):
        server = _make_server(db, password='root-pw')
        categories, mock_add = _run([server.id], ret={'success': True, 'server_id': 777})

        db.session.expire(server)  # перечитать из БД: проверяем реальный коммит
        assert server.vps_manager_server_id == 777
        assert server.ssh_port == 2233
        assert (server.id, server.name) in categories[CAT_CONNECTED]

        # Параметры вызова: порт из --port, category_ids не передаются.
        kwargs = mock_add.call_args.kwargs
        assert kwargs['ssh_port'] == 2233
        assert kwargs['password'] == 'root-pw'
        assert kwargs['name'] == server.name
        assert kwargs['ip_address'] == server.ip_address
        assert kwargs['username'] == 'root'
        assert 'category_ids' not in kwargs

        # Кастомный --port: тот же порт и в вызов, и в базу — одна граница
        # «ssh_port пишется при успехе», два порта.
        other = _make_server(db, name='vps-c1-port', password='pw')
        categories2, mock_add2 = _run(
            [other.id], ret={'success': True, 'server_id': 9}, port=2222,
        )
        db.session.expire(other)
        assert other.vps_manager_server_id == 9
        assert other.ssh_port == 2222
        assert mock_add2.call_args.kwargs['ssh_port'] == 2222


# --------------------------------------------------------------------------- #
# 1a. success: true без server_id — не успех: в базу ничего, в «достучались,
#     но операция не удалась»
# --------------------------------------------------------------------------- #

class TestSuccessWithoutServerId:

    def test_success_without_server_id_goes_to_failed(self, app, db):
        server = _make_server(db, password='pw')
        categories, mock_add = _run([server.id], ret={'success': True})

        mock_add.assert_called_once()
        # В базу ничего: NULL в vps_manager_server_id навсегда оставил бы сервер
        # «подключённым» без id — тихая порча данных, которую никто не заметит.
        db.session.expire(server)
        assert server.vps_manager_server_id is None
        assert server.ssh_port is None
        assert (
            server.id, server.name, 'VPS Manager вернул успех без server_id'
        ) in categories[CAT_FAILED]
        assert categories[CAT_CONNECTED] == []


# --------------------------------------------------------------------------- #
# 2. Уже подключённый сервер — категория, add_server не вызывается
# --------------------------------------------------------------------------- #

class TestAlreadyConnected:

    def test_already_connected_skips_call(self, app, db):
        server = _make_server(db, password='pw', vps_manager_server_id=42)
        categories, mock_add = _run([server.id])

        mock_add.assert_not_called()
        assert (server.id, server.name) in categories[CAT_ALREADY]


# --------------------------------------------------------------------------- #
# 3. Отбраковка до сети: своя категория, add_server не вызывается
# --------------------------------------------------------------------------- #

class TestPreNetworkRejection:

    def test_missing_server_goes_to_no_such(self, app, db):
        categories, mock_add = _run([99999])
        mock_add.assert_not_called()
        assert (99999, None) in categories[CAT_NO_SERVER]

    def test_empty_address_rejected(self, app, db):
        server = _make_server(db, password='pw', ip_address=None)
        categories, mock_add = _run([server.id])
        mock_add.assert_not_called()
        assert (server.id, server.name) in categories[CAT_NO_ADDR]

    def test_empty_password_rejected(self, app, db):
        server = _make_server(db)  # password не задан
        categories, mock_add = _run([server.id])
        mock_add.assert_not_called()
        assert (server.id, server.name) in categories[CAT_NO_PASSWORD]

    @pytest.mark.parametrize('username', ['-', '', '   '])
    def test_bad_ssh_username_rejected(self, app, db, username):
        server = _make_server(db, password='pw', ssh_username=username)
        categories, mock_add = _run([server.id])
        mock_add.assert_not_called()
        assert (server.id, server.name) in categories[CAT_BAD_USER]


# --------------------------------------------------------------------------- #
# 4. connection_refused не пишет в базу ничего, включая ssh_port
# --------------------------------------------------------------------------- #

class TestRefusalWritesNothing:

    def test_connection_refused_writes_nothing(self, app, db):
        server = _make_server(db, password='pw')
        categories, _ = _run(
            [server.id],
            ret={'success': False, 'error_type': 'connection_refused', 'message': 'down'},
        )

        db.session.expire(server)
        assert server.vps_manager_server_id is None
        assert server.ssh_port is None
        assert (server.id, server.name) in categories[CAT_UNREACHABLE]

    def test_timeout_same_category(self, app, db):
        server = _make_server(db, password='pw')
        categories, _ = _run(
            [server.id],
            ret={'success': False, 'error_type': 'timeout', 'message': 'slow'},
        )
        assert (server.id, server.name) in categories[CAT_UNREACHABLE]

    def test_duplicate_category(self, app, db):
        server = _make_server(db, password='pw')
        categories, _ = _run(
            [server.id],
            ret={'success': False, 'error_type': 'duplicate', 'message': 'dup'},
        )
        assert (server.id, server.name) in categories[CAT_DUPLICATE]


# --------------------------------------------------------------------------- #
# 5. bootstrap_request_id при повторном запуске переиспользуется
# --------------------------------------------------------------------------- #

class TestBootstrapRequestId:

    def test_bootstrap_request_id_reused_on_rerun(self, app, db):
        """Первый прогон упал (timeout) -> id закоммичен до вызова;

        повторный прогон обязан переиспользовать его, а не генерировать заново
        (иначе обрыв/ретрай заведёт в VPS Manager второй сервер).
        """
        server = _make_server(db, password='pw')

        _run([server.id], ret={'success': False, 'error_type': 'timeout', 'message': 'slow'})
        db.session.expire(server)
        first = server.bootstrap_request_id
        assert first is not None  # записан и закоммичен ещё до вызова

        categories, mock_add = _run([server.id], ret={'success': True, 'server_id': 55})
        assert mock_add.call_args.kwargs['bootstrap_request_id'] == first

        db.session.expire(server)
        assert server.bootstrap_request_id == first  # не перегенерирован
        assert server.vps_manager_server_id == 55

    def test_bootstrap_request_id_generated_and_persisted_on_success(self, app, db):
        server = _make_server(db, password='pw')
        categories, mock_add = _run([server.id], ret={'success': True, 'server_id': 7})

        assert mock_add.call_args.kwargs['bootstrap_request_id']  # непустой
        db.session.expire(server)
        assert server.bootstrap_request_id


# --------------------------------------------------------------------------- #
# 6. --dry-run: без сети и без записи в базу
# --------------------------------------------------------------------------- #

class TestDryRun:

    def test_dry_run_no_call_no_db_change(self, app, db):
        server = _make_server(db, password='pw')
        categories, mock_add = _run([server.id], dry_run=True)

        mock_add.assert_not_called()
        db.session.expire(server)
        assert server.vps_manager_server_id is None
        assert server.ssh_port is None
        assert server.bootstrap_request_id is None
        # Сухой прогон — в «прошли отбор (dry-run)», а не в «подключено»:
        # в хвосте отчёта не должно появиться «подключено: N» после прогона,
        # в котором не сделано ничего.
        assert (server.id, server.name) in categories[CAT_DRY_RUN]
        assert categories[CAT_CONNECTED] == []


# --------------------------------------------------------------------------- #
# 7. Root-пароль не появляется в выводе (в т.ч. на ветке отказа)
# --------------------------------------------------------------------------- #

class TestNoPasswordLeak:

    def test_password_not_in_output_mixed_run(self, app, db, capsys):
        ok_pass = 'Sup3r-Secret-Pass'
        boom_pass = 'B00m-Secret-Pass'
        fail_pass = 'An0ther-Secret-Pass'
        s_ok = _make_server(db, name='vps-c1-ok', password=ok_pass)
        s_boom = _make_server(db, name='vps-c1-boom', password=boom_pass)
        s_fail = _make_server(db, name='vps-c1-fail', password=fail_pass)

        def side_effect(**kwargs):
            if kwargs['name'] == s_ok.name:
                return {'success': True, 'server_id': 88}
            if kwargs['name'] == s_boom.name:
                raise RuntimeError('operation exploded')
            return {'success': False, 'error_type': 'server_error', 'message': 'operation failed'}

        with patch('scripts.connect_to_vps_manager.vps_client.add_server') as mock_add:
            mock_add.side_effect = side_effect
            categories = connect_servers([s_ok.id, s_fail.id, s_boom.id], port=2233)

        report_and_check(categories, 3)  # инвариант: исключение учтено

        out = capsys.readouterr().out
        assert ok_pass not in out
        assert boom_pass not in out
        assert fail_pass not in out
        # Ветка отказа отработала: ошибка в «достучались, но операция не удалась».
        assert (s_fail.id, s_fail.name, 'operation failed') in categories[CAT_FAILED]
        # Ветка исключения тоже в отчёте — и без пароля.
        assert (s_boom.id, s_boom.name, 'RuntimeError: operation exploded') in categories[CAT_ERROR]
        assert boom_pass not in categories[CAT_ERROR][0][2]


# --------------------------------------------------------------------------- #
# 7a. Исключение на одном сервере не убивает прогон
# --------------------------------------------------------------------------- #

class TestServerProcessingException:

    def test_exception_on_one_server_continues_and_reports(self, app, db, capsys):
        ok = _make_server(db, name='vps-c1-exc-ok', password='pw')
        boom = _make_server(db, name='vps-c1-exc-boom', password='pw')

        def side_effect(**kwargs):
            if kwargs['name'] == boom.name:
                raise RuntimeError('connection exploded')
            return {'success': True, 'server_id': 66}

        with patch('scripts.connect_to_vps_manager.vps_client.add_server') as mock_add:
            mock_add.side_effect = side_effect
            categories = connect_servers([boom.id, ok.id], port=2233)

        # Упавший учтён в «сбой при обработке», живой обработан, сумма сошлась.
        report_and_check(categories, 2)  # не должно бросить

        assert (
            boom.id, boom.name, 'RuntimeError: connection exploded'
        ) in categories[CAT_ERROR]
        assert (ok.id, ok.name) in categories[CAT_CONNECTED]
        db.session.expire(ok)
        assert ok.vps_manager_server_id == 66  # следующий обработан до конца

        out = capsys.readouterr().out
        assert CAT_ERROR in out  # отчёт напечатан
        assert 'connection exploded' in out


# --------------------------------------------------------------------------- #
# 8. Расхождение счётчиков -> RuntimeError (после печати отчёта)
# --------------------------------------------------------------------------- #

class LyingList(list):
    """Изображает запись, исчезнувшую не увеличив ни один счётчик."""

    def __len__(self):
        return super().__len__() + 1


class TestSumInvariant:

    def test_mismatch_raises_after_report_printed(self, app, db, capsys):
        categories = {CAT_CONNECTED: LyingList([(1, 'vps-1')])}

        with pytest.raises(RuntimeError) as excinfo:
            report_and_check(categories, 1)

        msg = str(excinfo.value)
        assert '1' in msg  # обработано
        assert '2' in msg  # разошлось
        # Отчёт напечатан до проверки.
        assert CAT_CONNECTED in capsys.readouterr().out

    def test_reconciles_when_counts_match(self, app, db, capsys):
        categories = {
            CAT_CONNECTED: [(1, 'vps-1')],
            CAT_UNREACHABLE: [(2, 'vps-2')],
            CAT_NO_SERVER: [(9, None)],
        }
        report_and_check(categories, 3)  # не должно бросить
        out = capsys.readouterr().out
        assert 'vps-1' in out
        assert 'vps-2' in out
        assert '#9' in out  # «нет такого сервера» — без имени


# --------------------------------------------------------------------------- #
# Полный прогон по нескольким id: каждый id ровно в одной категории
# --------------------------------------------------------------------------- #

class TestMixedRunInvariant:

    def test_every_id_accounted_exactly_once(self, app, db, capsys):
        ok = _make_server(db, name='vps-mix-ok', password='pw')
        dead = _make_server(db, name='vps-mix-dead', password='pw')

        def side_effect(**kwargs):
            if kwargs['name'] == ok.name:
                return {'success': True, 'server_id': 5}
            return {'success': False, 'error_type': 'connection_refused', 'message': 'x'}

        with patch('scripts.connect_to_vps_manager.vps_client.add_server') as mock_add:
            mock_add.side_effect = side_effect
            categories = connect_servers([ok.id, dead.id, 99999], port=2233)

        report_and_check(categories, 3)  # без RuntimeError: сумма сходится

        assert (ok.id, ok.name) in categories[CAT_CONNECTED]
        assert (dead.id, dead.name) in categories[CAT_UNREACHABLE]
        assert (99999, None) in categories[CAT_NO_SERVER]
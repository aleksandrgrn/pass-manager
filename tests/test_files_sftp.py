"""Окно файлов (SFTP) в строке сервера: доступ, лимиты, перезапись, журнал.

SSH не мокается: маршруты ходят на встроенный SFTP-сервер paramiko, поднятый
на 127.0.0.1 поверх временного каталога. Подменяется только VPS Manager —
`get_access_key`, который отдаёт сервисный ключ.
"""
from __future__ import annotations

import io
import os
import posixpath
import socket
import stat
import threading
from contextlib import suppress
from unittest.mock import patch

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.models import AccessAssignment, FileAccessLog, Server, ServerGroup
from app.services import sftp
from tests.conftest import login_as

# --------------------------------------------------------------------------- #
# Встроенный SFTP-сервер
# --------------------------------------------------------------------------- #

def _openssh_key() -> str:
    """Ключ в том же формате, в каком его отдаёт VPS Manager на проде (OPENSSH)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()


@pytest.fixture(scope='session')
def service_key() -> str:
    return _openssh_key()


@pytest.fixture(scope='session')
def other_key() -> str:
    return _openssh_key()


@pytest.fixture(scope='session')
def host_key() -> paramiko.PKey:
    return paramiko.RSAKey.generate(2048)


class _Auth(paramiko.ServerInterface):
    def __init__(self, allowed: paramiko.PKey):
        self.allowed = allowed

    def get_allowed_auths(self, username):
        return 'publickey'

    def check_auth_publickey(self, username, key):
        if username == 'root' and key == self.allowed:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


class _Handle(paramiko.SFTPHandle):
    def stat(self):
        return paramiko.SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))


class _RootedSFTP(paramiko.SFTPServerInterface):
    """Файловая система сервера — временный каталог ROOT, «/» клиента = ROOT."""
    ROOT = ''
    chowns: list  # задаёт фикстура vps

    def canonicalize(self, path):
        real = os.path.realpath(self.ROOT + posixpath.normpath('/' + path))
        return real[len(self.ROOT):] or '/'

    def _real(self, path):
        return self.ROOT + posixpath.normpath('/' + path)

    def list_folder(self, path):
        real = self._real(path)
        try:
            out = []
            for name in os.listdir(real):
                attr = paramiko.SFTPAttributes.from_stat(os.lstat(os.path.join(real, name)))
                attr.filename = name
                out.append(attr)
            return out
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(self._real(path)))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        try:
            fd = os.open(self._real(path), flags, 0o644)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        mode = 'rb' if flags & (os.O_WRONLY | os.O_RDWR) == 0 else 'wb'
        f = os.fdopen(fd, mode)
        handle = _Handle(flags)
        handle.filename = self._real(path)
        handle.readfile = f
        handle.writefile = f
        return handle

    def remove(self, path):
        try:
            os.remove(self._real(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def rename(self, oldpath, newpath):
        # Как OpenSSH: занятое имя не затирается.
        try:
            os.link(self._real(oldpath), self._real(newpath))
            os.remove(self._real(oldpath))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def posix_rename(self, oldpath, newpath):
        try:
            os.replace(self._real(oldpath), self._real(newpath))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def chattr(self, path, attr):
        # Владельца тест не меняет (прогон может идти не от root) — запоминает,
        # что клиент об этом попросил.
        try:
            if attr.st_mode is not None:
                os.chmod(self._real(path), attr.st_mode)
            if attr.st_uid is not None:
                self.chowns.append((path, attr.st_uid, attr.st_gid))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK


class _Vps:
    """Запущенный сервер: порт, корень файловой системы, запросы chown."""

    def __init__(self, port, root, chowns):
        self.port = port
        self.root = root
        self.chowns = chowns

    def leftovers(self):
        """Временные файлы загрузки, оставшиеся на сервере."""
        return [
            name for _, _, names in os.walk(self.root) for name in names
            if '.pm-upload-' in name
        ]


@pytest.fixture()
def vps(tmp_path, service_key, host_key):
    root = tmp_path / 'vps'
    root.mkdir()
    (root / 'etc').mkdir()
    (root / 'etc' / 'app.conf').write_text('listen 8080\n')
    (root / 'notes.txt').write_text('привет\n')

    allowed = paramiko.RSAKey.from_private_key(io.StringIO(service_key))
    chowns: list = []
    si = type('SFTP', (_RootedSFTP,), {'ROOT': str(root), 'chowns': chowns})

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(5)
    transports = []

    def _serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            transport = paramiko.Transport(conn)
            transport.add_server_key(host_key)
            transport.set_subsystem_handler('sftp', paramiko.SFTPServer, si)
            transports.append(transport)
            with suppress(paramiko.SSHException, EOFError, OSError):
                transport.start_server(server=_Auth(allowed))

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    yield _Vps(listener.getsockname()[1], root, chowns)
    listener.close()
    for transport in transports:
        transport.close()


# --------------------------------------------------------------------------- #
# Данные и запросы
# --------------------------------------------------------------------------- #

@pytest.fixture()
def server(db, sample_server, vps):
    """Сервер группы admin_user, привязанный к VPS Manager и смотрящий на vps."""
    sample_server.ip_address = '127.0.0.1'
    sample_server.ssh_port = vps.port
    sample_server.vps_manager_server_id = 42
    db.session.commit()
    return sample_server


def _grant(db, user, server, state='active'):
    db.session.add(AccessAssignment(
        server_id=server.id, user_id=user.id, state=state, granted_by=user.id,
    ))
    db.session.commit()


@pytest.fixture()
def granted(db, admin_user, server):
    _grant(db, admin_user, server)


@pytest.fixture()
def access_key(service_key):
    """VPS Manager отдаёт сервисный ключ сервера."""
    with patch('app.servers.views.vps_client.get_access_key',
               return_value={'success': True, 'private_key': service_key}) as mock:
        yield mock


def _list(client, server, path=None):
    query = {'path': path} if path is not None else None
    return client.get(f'/servers/{server.id}/files', query_string=query)


def _download(client, server, path='/notes.txt'):
    return client.get(f'/servers/{server.id}/files/download', query_string={'path': path})


def _upload(client, server, path='/etc', name='new.conf', data=b'x=1\n', overwrite=False):
    form = {'path': path, 'file': (io.BytesIO(data), name)}
    if overwrite:
        form['overwrite'] = '1'
    return client.post(f'/servers/{server.id}/files/upload', data=form,
                       content_type='multipart/form-data')


ROUTES = {'list': _list, 'download': _download, 'upload': _upload}


def _logs():
    return FileAccessLog.query.order_by(FileAccessLog.id).all()


# --------------------------------------------------------------------------- #
# Матрица доступа: три маршрута × шесть положений
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('action', ROUTES)
class TestAccessMatrix:

    def _assert_denied(self, resp, access_key, action, user):
        assert resp.status_code == 403
        # Отказ — до любого обращения за ключом и к серверу.
        access_key.assert_not_called()
        [row] = _logs()
        assert (row.action, row.result, row.user_id) == (action, 'denied', user.id)

    def test_active_grant_allowed(self, action, admin_client, server, granted, access_key):
        resp = ROUTES[action](admin_client, server)
        assert resp.status_code == 200
        access_key.assert_called_once_with(42)
        [row] = _logs()
        assert (row.action, row.result, row.server_id) == (action, 'ok', server.id)

    def test_no_grant_denied(self, action, admin_client, admin_user, server, access_key):
        # Сервер своей группы виден, но выдачи нет — файлов нет.
        resp = ROUTES[action](admin_client, server)
        self._assert_denied(resp, access_key, action, admin_user)

    def test_revoked_grant_denied(self, action, db, admin_client, admin_user, server, access_key):
        _grant(db, admin_user, server, state='revoked')
        resp = ROUTES[action](admin_client, server)
        self._assert_denied(resp, access_key, action, admin_user)

    def test_unlinked_server_denied(self, action, db, admin_client, admin_user, server,
                                    granted, access_key):
        server.vps_manager_server_id = None
        db.session.commit()
        resp = ROUTES[action](admin_client, server)
        self._assert_denied(resp, access_key, action, admin_user)

    def test_superadmin_denied(self, action, db, superadmin_client, superadmin_user,
                               server, access_key):
        # Даже с активной выдачей: суперадмин на VPS не ходит (Р5).
        _grant(db, superadmin_user, server)
        resp = ROUTES[action](superadmin_client, server)
        self._assert_denied(resp, access_key, action, superadmin_user)

    def test_foreign_group_denied(self, action, db, admin_client, admin_user, server, access_key):
        foreign = ServerGroup(name='foreign')
        db.session.add(foreign)
        db.session.commit()
        server.group_id = foreign.id
        db.session.commit()
        resp = ROUTES[action](admin_client, server)
        self._assert_denied(resp, access_key, action, admin_user)

    def test_anonymous_redirected_to_login(self, action, client, server, access_key):
        resp = ROUTES[action](client, server)
        assert resp.status_code == 302 and '/auth/login' in resp.headers['Location']
        access_key.assert_not_called()
        assert _logs() == []


def test_denied_upload_writes_nothing(admin_client, server, vps, access_key):
    resp = _upload(admin_client, server)
    assert resp.status_code == 403
    assert not (vps.root / 'etc' / 'new.conf').exists()


# --------------------------------------------------------------------------- #
# Список каталога
# --------------------------------------------------------------------------- #

def test_list_starts_in_home_dir(admin_client, server, granted, access_key):
    body = _list(admin_client, server).get_data(as_text=True)
    assert 'notes.txt' in body and 'etc' in body
    assert 'data-files-dir="/etc"' in body
    assert 'data-files-download="/notes.txt"' in body


def test_list_subdirectory(admin_client, server, granted, access_key):
    body = _list(admin_client, server, '/etc').get_data(as_text=True)
    assert 'app.conf' in body and 'notes.txt' not in body
    assert 'data-files-dir="/"' in body  # переход наверх
    assert _logs()[0].path == '/etc'


def test_list_is_truncated(admin_client, server, granted, access_key, vps, monkeypatch):
    monkeypatch.setattr(sftp, 'MAX_ENTRIES', 3)
    for i in range(5):
        (vps.root / f'f{i}').write_text('')
    body = _list(admin_client, server).get_data(as_text=True)
    assert body.count('data-files-download=') + body.count('data-files-entry-dir') == 3
    assert 'Показаны первые 3' in body


def test_list_missing_directory(admin_client, server, granted, access_key):
    resp = _list(admin_client, server, '/nope')
    assert resp.status_code == 404
    assert 'Нет такого файла или каталога' in resp.get_data(as_text=True)
    assert _logs()[0].result == 'error'


def test_list_shows_symlinked_directory_as_directory(admin_client, server, granted, access_key, vps):
    (vps.root / 'conf').symlink_to('etc')
    (vps.root / 'broken').symlink_to('nowhere')
    body = _list(admin_client, server).get_data(as_text=True)
    assert 'data-files-dir="/conf"' in body
    assert 'data-files-download="/broken"' in body


def test_list_escapes_file_names(admin_client, server, granted, access_key, vps):
    (vps.root / '<img src=x onerror=alert(1)>').write_text('')
    body = _list(admin_client, server).get_data(as_text=True)
    assert '<img src=x' not in body


# --------------------------------------------------------------------------- #
# Скачивание
# --------------------------------------------------------------------------- #

def test_download_returns_attachment(admin_client, server, granted, access_key):
    resp = _download(admin_client, server, '/etc/app.conf')
    assert resp.data == b'listen 8080\n'
    assert resp.headers['Content-Disposition'].startswith('attachment')
    assert 'app.conf' in resp.headers['Content-Disposition']
    assert resp.headers['Content-Type'] == 'application/octet-stream'
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    [row] = _logs()
    assert (row.path, row.size) == ('/etc/app.conf', 12)


def test_download_over_limit_refused(admin_client, server, granted, access_key, vps, monkeypatch):
    monkeypatch.setattr(sftp, 'MAX_FILE_SIZE', 10)
    (vps.root / 'big.bin').write_bytes(b'0' * 11)
    resp = _download(admin_client, server, '/big.bin')
    assert resp.status_code == 413
    assert 'больше' in resp.get_data(as_text=True)
    assert resp.headers['Content-Type'].startswith('text/plain')
    assert _logs()[0].result == 'error'


def test_download_at_limit_allowed(admin_client, server, granted, access_key, vps, monkeypatch):
    monkeypatch.setattr(sftp, 'MAX_FILE_SIZE', 10)
    (vps.root / 'ok.bin').write_bytes(b'0' * 10)
    assert _download(admin_client, server, '/ok.bin').data == b'0' * 10


def test_download_directory_refused(admin_client, server, granted, access_key):
    resp = _download(admin_client, server, '/etc')
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Загрузка
# --------------------------------------------------------------------------- #

def test_upload_creates_file_0644(admin_client, admin_user, server, granted, access_key, vps):
    resp = _upload(admin_client, server, data=b'x=1\n')
    assert resp.status_code == 200
    target = vps.root / 'etc' / 'new.conf'
    assert target.read_bytes() == b'x=1\n'
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert vps.leftovers() == []
    # Ответ — перерисованный каталог с новым файлом.
    assert 'new.conf' in resp.get_data(as_text=True)
    [row] = _logs()
    assert (row.action, row.result, row.path, row.size, row.user_id) == (
        'upload', 'ok', '/etc/new.conf', 4, admin_user.id)


def test_upload_ok_but_listing_failed_is_reported(admin_client, server, granted, access_key, vps,
                                                  monkeypatch):
    def _broken(session, path):
        raise sftp.SftpError('Сервер не ответил вовремя.')
    monkeypatch.setattr(sftp, 'list_dir', _broken)
    resp = _upload(admin_client, server)
    assert resp.status_code == 502
    assert 'Файл загружен' in resp.get_data(as_text=True)
    assert (vps.root / 'etc' / 'new.conf').exists()
    assert [(r.action, r.result) for r in _logs()] == [('upload', 'ok'), ('list', 'error')]


def test_upload_over_limit_refused(admin_client, server, granted, access_key, vps, monkeypatch):
    monkeypatch.setattr(sftp, 'MAX_FILE_SIZE', 10)
    resp = _upload(admin_client, server, data=b'0' * 11)
    assert resp.status_code == 413
    assert not (vps.root / 'etc' / 'new.conf').exists()
    assert vps.leftovers() == []
    assert _logs()[0].result == 'error'


def test_upload_at_limit_allowed(admin_client, server, granted, access_key, vps, monkeypatch):
    monkeypatch.setattr(sftp, 'MAX_FILE_SIZE', 10)
    assert _upload(admin_client, server, data=b'0' * 10).status_code == 200


def test_body_limit_is_set_for_the_whole_app(app):
    # Файл в 5 МБ с обвязкой multipart должен проходить, тело заметно больше — нет.
    assert sftp.MAX_FILE_SIZE < app.config['MAX_CONTENT_LENGTH'] <= 6 * 1024 * 1024


def test_upload_oversized_body_refused_before_ssh(app, admin_client, server, granted, access_key, vps):
    # Тело больше предела отсекается по Content-Length, до похода за ключом.
    app.config['MAX_CONTENT_LENGTH'] = 1000
    resp = _upload(admin_client, server, data=b'0' * 5000)
    assert resp.status_code == 413
    access_key.assert_not_called()
    assert not (vps.root / 'etc' / 'new.conf').exists()


def test_oversized_extra_form_part_refused_with_csrf_on(app, admin_client, server, granted,
                                                        access_key):
    # Форму первым разбирает CSRF — предел должен действовать уже там.
    app.config['MAX_CONTENT_LENGTH'] = 1000
    app.config['WTF_CSRF_ENABLED'] = True
    resp = admin_client.post(
        f'/servers/{server.id}/files/upload',
        data={'path': '/etc', 'file': (io.BytesIO(b'x'), 'new.conf'), 'junk': 'j' * 5000},
        content_type='multipart/form-data')
    assert resp.status_code == 413
    access_key.assert_not_called()


def test_upload_requires_csrf_token(app, admin_client, server, granted, access_key, vps):
    app.config['WTF_CSRF_ENABLED'] = True
    resp = _upload(admin_client, server)
    assert resp.status_code == 400
    access_key.assert_not_called()
    assert not (vps.root / 'etc' / 'new.conf').exists()


def test_upload_over_dangling_symlink_refused(admin_client, server, granted, access_key, vps):
    link = vps.root / 'etc' / 'new.conf'
    link.symlink_to('missing.conf')
    for overwrite in (False, True):
        resp = _upload(admin_client, server, overwrite=overwrite)
        assert resp.status_code == 400
    assert link.is_symlink() and not (vps.root / 'etc' / 'missing.conf').exists()
    assert vps.leftovers() == []


def test_upload_does_not_clobber_file_created_meanwhile(server, vps, service_key):
    # Гонка двух загрузок: имя было свободно при проверке, но занято к концу записи.
    class Racing:
        def __init__(self, real):
            self.real = real

        def __getattr__(self, name):
            return getattr(self.real, name)

        def open(self, path, mode):
            (vps.root / 'etc' / 'new.conf').write_text('чужой\n')
            return self.real.open(path, mode)

    with sftp.connect('127.0.0.1', vps.port, 'root', service_key) as session, \
            pytest.raises(sftp.SftpError) as exc:
        sftp.write_file(Racing(session), '/etc', 'new.conf', b'my\n', overwrite=False)
    assert exc.value.status == 409
    assert (vps.root / 'etc' / 'new.conf').read_text() == 'чужой\n'
    assert vps.leftovers() == []


def test_list_does_not_swallow_timeout_on_symlink(server, vps, service_key):
    (vps.root / 'conf').symlink_to('etc')

    class Silent:
        def __init__(self, real):
            self.real = real

        def __getattr__(self, name):
            return getattr(self.real, name)

        def stat(self, path):
            raise TimeoutError

    with sftp.connect('127.0.0.1', vps.port, 'root', service_key) as session, \
            pytest.raises(sftp.SftpError, match='не ответил'):
        sftp.list_dir(Silent(session), '/')


def test_upload_over_existing_needs_confirmation(admin_client, server, granted, access_key, vps):
    resp = _upload(admin_client, server, name='app.conf', data=b'new\n')
    assert resp.status_code == 409
    assert (vps.root / 'etc' / 'app.conf').read_text() == 'listen 8080\n'
    assert vps.leftovers() == []
    assert _logs()[0].result == 'error'


def test_upload_overwrite_keeps_mode_and_owner(admin_client, server, granted, access_key, vps):
    target = vps.root / 'etc' / 'app.conf'
    target.chmod(0o600)
    owner = target.stat()
    resp = _upload(admin_client, server, name='app.conf', data=b'new\n', overwrite=True)
    assert resp.status_code == 200
    assert target.read_bytes() == b'new\n'
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [(uid, gid) for _, uid, gid in vps.chowns] == [(owner.st_uid, owner.st_gid)]
    assert vps.leftovers() == []


def test_upload_over_symlink_writes_through(admin_client, server, granted, access_key, vps):
    # Как обычный SFTP: ссылка остаётся ссылкой, меняется файл, на который она смотрит.
    (vps.root / 'etc' / 'link.conf').symlink_to('app.conf')
    resp = _upload(admin_client, server, name='link.conf', data=b'new\n', overwrite=True)
    assert resp.status_code == 200
    assert (vps.root / 'etc' / 'link.conf').is_symlink()
    assert (vps.root / 'etc' / 'app.conf').read_bytes() == b'new\n'
    assert _logs()[0].path == '/etc/app.conf'


def test_upload_over_directory_refused(admin_client, server, granted, access_key, vps):
    (vps.root / 'etc' / 'dir').mkdir()
    resp = _upload(admin_client, server, name='dir', overwrite=True)
    assert resp.status_code == 400
    assert (vps.root / 'etc' / 'dir').is_dir()


def test_upload_name_cannot_leave_directory(admin_client, server, granted, access_key, vps):
    resp = _upload(admin_client, server, name='../../evil.conf')
    assert resp.status_code == 200
    assert (vps.root / 'etc' / 'evil.conf').exists()
    assert not (vps.root / 'evil.conf').exists()


def test_upload_without_file_refused(admin_client, server, granted, access_key):
    resp = admin_client.post(f'/servers/{server.id}/files/upload', data={'path': '/etc'})
    assert resp.status_code == 400


@pytest.mark.parametrize('name', ['', '.', '..', 'a/b', 'a\x00b'])
def test_write_file_rejects_bad_names(name):
    with pytest.raises(sftp.SftpError):
        sftp.write_file(None, '/etc', name, b'', overwrite=False)


# --------------------------------------------------------------------------- #
# Отказы VPS Manager и SSH
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('action', ROUTES)
def test_vps_manager_error_is_reported(action, admin_client, server, granted):
    with patch('app.servers.views.vps_client.get_access_key',
               return_value={'success': False, 'message': 'Сервер не найден'}):
        resp = ROUTES[action](admin_client, server)
    assert resp.status_code == 502
    body = resp.get_data(as_text=True)
    assert 'VPS Manager' in body and 'Сервер не найден' in body
    [row] = _logs()
    assert (row.action, row.result) == (action, 'error')


@pytest.mark.parametrize('action', ROUTES)
def test_rejected_key_is_reported(action, admin_client, server, granted, other_key):
    with patch('app.servers.views.vps_client.get_access_key',
               return_value={'success': True, 'private_key': other_key}):
        resp = ROUTES[action](admin_client, server)
    assert resp.status_code == 502
    assert 'не принял сервисный ключ' in resp.get_data(as_text=True)
    assert other_key.splitlines()[1] not in resp.get_data(as_text=True)
    assert _logs()[0].result == 'error'


def test_unreachable_server_is_reported(db, admin_client, server, granted, access_key):
    closed = socket.socket()
    closed.bind(('127.0.0.1', 0))
    server.ssh_port = closed.getsockname()[1]  # порт занят, но не слушается
    db.session.commit()
    resp = _list(admin_client, server)
    closed.close()
    assert resp.status_code == 502
    assert 'Не удалось подключиться' in resp.get_data(as_text=True)


def test_garbage_key_is_reported(admin_client, server, granted):
    with patch('app.servers.views.vps_client.get_access_key',
               return_value={'success': True, 'private_key': 'not a key'}):
        resp = _list(admin_client, server)
    assert resp.status_code == 502
    assert 'not a key' not in resp.get_data(as_text=True)


# --------------------------------------------------------------------------- #
# Кнопка в строке сервера
# --------------------------------------------------------------------------- #

def _row_html(client):
    return client.get('/servers/').get_data(as_text=True)


def test_button_active_with_grant(admin_client, server, granted):
    html = _row_html(admin_client)
    assert f'data-files-url="/servers/{server.id}/files"' in html


def test_button_grey_without_grant(admin_client, server):
    html = _row_html(admin_client)
    assert 'data-files-url="' not in html
    assert f'id="files-btn-{server.id}"' in html
    button = html.split(f'id="files-btn-{server.id}"')[1].split('>')[0]
    assert 'disabled' in button and 'доступ' in button


def test_button_grey_on_unlinked_server(db, admin_client, server, granted):
    server.vps_manager_server_id = None
    db.session.commit()
    html = _row_html(admin_client)
    assert 'data-files-url="' not in html
    button = html.split(f'id="files-btn-{server.id}"')[1].split('>')[0]
    assert 'disabled' in button and 'VPS Manager' in button


def test_superadmin_has_no_button(db, superadmin_client, superadmin_user, server):
    _grant(db, superadmin_user, server)
    html = _row_html(superadmin_client)
    assert 'files-btn-' not in html


def test_button_appears_after_self_grant(admin_client, server):
    with patch('app.servers.views.vps_client.generate_key', return_value={'success': True, 'id': 7}), \
            patch('app.servers.views.vps_client.deploy_key', return_value={'success': True}):
        resp = admin_client.post(f'/servers/{server.id}/grant-self', headers={'HX-Request': 'true'})
    assert f'data-files-url="/servers/{server.id}/files"' in resp.get_data(as_text=True)


def test_two_users_are_logged_separately(app, db, admin_client, admin_user, server, granted,
                                        access_key, superadmin_user):
    _download(admin_client, server)
    other = app.test_client()
    login_as(other, 'superadmin_test')
    _download(other, server)
    assert [(r.user_id, r.result) for r in _logs()] == [
        (admin_user.id, 'ok'), (superadmin_user.id, 'denied')]
    assert Server.query.count() == 1


# --------------------------------------------------------------------------- #
# Миграция журнала
# --------------------------------------------------------------------------- #

def test_migration_creates_log_table_once(app, db):
    from sqlalchemy import inspect

    from scripts.migrate_sftp import TABLE, migrate

    def tables():
        return inspect(db.engine).get_table_names()

    FileAccessLog.__table__.drop(db.engine)
    assert TABLE not in tables()
    assert migrate(dry_run=True) is True
    assert TABLE not in tables()
    assert migrate(dry_run=False) is True
    assert TABLE in tables()
    assert migrate(dry_run=False) is False

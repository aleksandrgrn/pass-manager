"""Файлы на VPS по SFTP: список каталога, чтение, запись.

Без Flask-зависимостей, как `rotate.py`. Ключ приходит строкой и живёт только
в памяти — на диск не пишется. Все отказы наружу выходят одним типом,
`SftpError`, с текстом для человека и HTTP-статусом для маршрута.
"""
from __future__ import annotations

import errno
import io
import posixpath
import secrets
import stat
import threading
from contextlib import contextmanager, suppress
from datetime import datetime

import paramiko

# Таймауты обязательны — иначе повисший SSH держит воркер gunicorn.
CONNECT_TIMEOUT = 30
OP_TIMEOUT = 30
# Меньше 60 с, после которых nginx сам ответит 504: человек не должен увидеть
# отказ, пока операция на сервере ещё идёт.
SESSION_TIMEOUT = 50

# Окно — для ключей служб, сертификатов и конфигов, не для дампов.
MAX_FILE_SIZE = 5 * 1024 * 1024
# Каталог со ста тысячами файлов не должен вешать окно.
MAX_ENTRIES = 1000

NEW_FILE_MODE = 0o644


class SftpError(Exception):
    """Отказ с текстом для человека; `status` — HTTP-статус ответа маршрута."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def _too_large() -> SftpError:
    return SftpError(f'Файл больше {MAX_FILE_SIZE // (1024 * 1024)} МБ — через это окно не передаётся.', 413)


def _timed_out() -> SftpError:
    return SftpError(f'Сервер не уложился в {SESSION_TIMEOUT} с — операция прервана.', 504)


def _load_key(text: str) -> paramiko.PKey:
    for cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except paramiko.SSHException:
            continue
    # Текст исключений paramiko сюда не попадает: в нём может быть кусок ключа.
    raise SftpError('VPS Manager отдал ключ в неизвестном формате.')


@contextmanager
def connect(host: str, port: int, username: str, private_key: str, spent: float = 0):
    """SFTP-сессия по сервисному ключу сервера.

    AutoAddPolicy — как в ротации пароля: отпечатков у приложения нет, риск
    подмены хоста в сети принят (решение Р9).

    `spent` — сколько секунд общего срока уже ушло до подключения (получение
    ключа): срок один на весь запрос, а не только на SSH.
    """
    budget = SESSION_TIMEOUT - spent
    if budget <= 0:
        raise _timed_out()
    pkey = _load_key(private_key)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Общий срок на весь запрос — получение ключа, подключение и операции. Таймауты
    # paramiko его не дают: ответа на запрос подсистемы он ждёт без таймаута
    # вовсе, а таймаут канала считается на каждое чтение, и сервер, цедящий
    # данные по капле, держал бы воркер часами. По истечении срока соединение
    # закрывается, и застрявший вызов падает.
    expired = threading.Event()

    def _expire():
        expired.set()
        client.close()

    watchdog = threading.Timer(budget, _expire)
    watchdog.daemon = True
    watchdog.start()
    try:
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                pkey=pkey,
                timeout=CONNECT_TIMEOUT,
                banner_timeout=CONNECT_TIMEOUT,
                auth_timeout=CONNECT_TIMEOUT,
                # Только выданный per-server ключ: без этого paramiko при неудаче
                # молча пробует ssh-agent и ~/.ssh/id_* пользователя процесса.
                allow_agent=False,
                look_for_keys=False,
            )
            # Не client.open_sftp(): он согласует версию SFTP на канале без
            # таймаута.
            channel = client.get_transport().open_session(timeout=CONNECT_TIMEOUT)
            channel.settimeout(OP_TIMEOUT)
            channel.invoke_subsystem('sftp')
            session = paramiko.SFTPClient(channel)
        except paramiko.AuthenticationException:
            raise SftpError('Сервер не принял сервисный ключ.')
        except (paramiko.SSHException, OSError, EOFError) as e:
            if expired.is_set():
                raise _timed_out()
            raise SftpError(f'Не удалось подключиться к серверу: {e}')
        try:
            yield session
        except SftpError:
            if expired.is_set():
                raise _timed_out()
            raise
    finally:
        watchdog.cancel()
        client.close()


@contextmanager
def _errors():
    """Ошибки SFTP-операций — в SftpError с понятным текстом."""
    try:
        yield
    except SftpError:
        raise
    except TimeoutError:
        raise SftpError('Сервер не ответил вовремя.')
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise SftpError('Нет такого файла или каталога.', 404)
        if e.errno == errno.EACCES:
            raise SftpError('Сервер отказал: нет прав.')
        raise SftpError(f'Ошибка SFTP: {e}')
    except (paramiko.SSHException, EOFError):
        raise SftpError('Соединение с сервером оборвалось.')


def list_dir(session, path: str) -> dict:
    """Каталог `path` (пустой — домашний каталог SSH-пользователя).

    Возвращает path, parent (None у корня), entries и truncated. С сервера
    читаются только первые MAX_ENTRIES записей, в том порядке, в каком он их
    отдаёт; показываются они так: сначала каталоги, внутри — по имени.
    """
    with _errors():
        path = session.normalize(path or '.')
        # Обход обрывается на пределе: каталог со ста тысячами файлов не должен
        # ни читаться целиком, ни сортироваться. Ссылки разбираются ниже, после
        # обхода: listdir_iter читает ответы сервера сам, и stat посреди него
        # забирает чужой ответ — обход виснет до таймаута.
        found = []
        truncated = False
        for attr in session.listdir_iter(path):
            if len(found) >= MAX_ENTRIES:
                truncated = True
                break
            full = posixpath.join(path, attr.filename)
            found.append((not stat.S_ISDIR(attr.st_mode or 0), attr.filename.casefold(), full, attr))
        found.sort(key=lambda item: item[:3])
        entries = []
        for _, _, full, attr in found:
            if stat.S_ISLNK(attr.st_mode or 0):
                try:
                    attr = session.stat(full)  # куда смотрит ссылка
                except TimeoutError:
                    raise  # сервер замолчал — не ждать по таймауту на каждую ссылку
                except OSError:
                    pass  # битая ссылка — покажем как файл
            entries.append({
                'name': posixpath.basename(full),
                'path': full,
                'is_dir': stat.S_ISDIR(attr.st_mode or 0),
                'size': attr.st_size,
                # Время — в часовом поясе хоста Pass Manager, как и остальной интерфейс.
                'mtime': datetime.fromtimestamp(attr.st_mtime).strftime('%Y-%m-%d %H:%M')  # noqa: DTZ006
                if attr.st_mtime else '',
            })
    return {
        'path': path,
        'parent': posixpath.dirname(path) if path != '/' else None,
        'entries': entries,
        'truncated': truncated,
    }


def read_file(session, path: str) -> bytes:
    """Содержимое файла; больше MAX_FILE_SIZE — отказ до чтения."""
    with _errors():
        attr = session.stat(path)
        if stat.S_ISDIR(attr.st_mode):
            raise SftpError('Это каталог, а не файл.', 400)
        if not stat.S_ISREG(attr.st_mode):
            # FIFO или устройство: чтение висело бы до таймаута.
            raise SftpError('Это не обычный файл.', 400)
        if attr.st_size > MAX_FILE_SIZE:
            raise _too_large()
        with session.open(path, 'rb') as f:
            # +1 байт: у файлов вроде /proc/* размер в stat нулевой.
            data = f.read(MAX_FILE_SIZE + 1)
    if len(data) > MAX_FILE_SIZE:
        raise _too_large()
    return data


def validate_upload(filename: str, size: int) -> None:
    """Проверки загрузки, для которых сервер не нужен."""
    if not filename or filename in ('.', '..') or '/' in filename or '\x00' in filename:
        raise SftpError('Недопустимое имя файла.', 400)
    if size > MAX_FILE_SIZE:
        raise _too_large()


def _exists(session, path: str) -> bool:
    try:
        session.lstat(path)
    except OSError:
        return False
    return True


def write_file(session, directory: str, filename: str, data: bytes, overwrite: bool) -> str:
    """Кладёт файл в каталог и возвращает его итоговый путь.

    Без `overwrite` существующий файл не трогается никогда — даже если он
    появился, пока шла запись.

    Запись идёт во временный файл рядом и переименованием встаёт на место:
    обрыв связи не оставит на сервере половину конфига. Новый файл получает
    0644; при перезаписи права и владелец прежнего файла сохраняются, а ссылка
    остаётся ссылкой — меняется файл, на который она смотрит (так ведёт себя
    обычный SFTP).
    """
    validate_upload(filename, len(data))
    with _errors():
        target = posixpath.join(session.normalize(directory), filename)
        try:
            # lstat, а не stat: ссылка в никуда — тоже занятое имя.
            old = session.lstat(target)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            old = None
        if old is not None and stat.S_ISLNK(old.st_mode):
            try:
                old = session.stat(target)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise
                raise SftpError('С таким именем здесь ссылка на несуществующий файл.', 400)
        if old is not None:
            if stat.S_ISDIR(old.st_mode):
                raise SftpError('С таким именем здесь каталог.', 400)
            if not stat.S_ISREG(old.st_mode):
                raise SftpError('С таким именем здесь не обычный файл.', 400)
            if not overwrite:
                raise SftpError('Файл с таким именем уже есть.', 409)
            target = session.normalize(target)

        # Временный файл живёт в своём каталоге с правами 0700. SFTP создаёт
        # файл с правами по umask (обычно 0644), и chmod следом опоздал бы:
        # кто успел открыть файл, прочтёт и то, что в него запишут позже.
        # В закрытый каталог посторонний не войдёт вовсе. Имя короткое и от
        # имени файла не зависит: иначе файл с именем под предел в 255 байт
        # не загрузился бы.
        tmpdir = posixpath.join(posixpath.dirname(target), f'.pm-upload-{secrets.token_hex(8)}')
        tmp = posixpath.join(tmpdir, 'file')
        created = False
        try:
            session.mkdir(tmpdir, 0o700)  # занятое имя — отказ, чужое не трогаем
            created = True
            with session.open(tmp, 'wx') as f:
                f.write(data)
            if old is not None:
                session.chown(tmp, old.st_uid, old.st_gid)
                session.chmod(tmp, stat.S_IMODE(old.st_mode))
            else:
                session.chmod(tmp, NEW_FILE_MODE)
            if old is not None:
                session.posix_rename(tmp, target)
            else:
                # Обычный rename чужой файл не затирает: если имя заняли, пока
                # шла запись, это отказ, а не молчаливая замена.
                try:
                    session.rename(tmp, target)
                except OSError:
                    if _exists(session, target):
                        raise SftpError('Файл с таким именем уже есть.', 409)
                    raise
        except BaseException:
            # Временный файл за собой убираем — но только свой: если имя было
            # занято, там чужое. Не вышло убрать — исходная ошибка важнее.
            if created:
                with suppress(OSError, paramiko.SSHException, EOFError):
                    session.remove(tmp)
            raise
        finally:
            if created:
                with suppress(OSError, paramiko.SSHException, EOFError):
                    session.rmdir(tmpdir)
    return target

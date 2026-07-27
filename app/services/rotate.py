"""Ротация root-пароля по SSH (Track C, срез A3.2).

Отдельный модуль (не часть `provisioning.py`) — используется и pipeline'ом
онбординга (шаг `rotate`), и будущей кнопкой ad-hoc rotate (N2).

Р2 (specs/track-c-plan-A3.md): пароль передаётся в `chpasswd` через stdin,
а не `echo ... | chpasswd` — это протаскивает пароль через shell (экранирование,
видимость в списке процессов). Экранирование не нужно в принципе, пароль
в argv не попадает.
"""
from __future__ import annotations

import secrets
import string

import paramiko

# Таймауты обязательны — иначе повисший SSH держит шаг pipeline'а вечно.
CONNECT_TIMEOUT = 30
EXEC_TIMEOUT = 30

# Р5: алфавит без `:` (разделитель формата chpasswd), пробельных символов,
# кавычек, backslash и `$`.
_PASSWORD_ALPHABET = string.ascii_letters + string.digits + '!#%*+-=?@^_'
_PASSWORD_LENGTH = 24


class RotateError(Exception):
    """chpasswd на target вернул ненулевой exit_status."""


def generate_password() -> str:
    """Р5: 24 символа по алфавиту, безопасному для chpasswd/stdin."""
    return ''.join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(_PASSWORD_LENGTH))


def rotate_root(host: str, port: int, key_path: str, username: str, new_password: str) -> None:
    """Меняет пароль `username` на target через `chpasswd` (пароль — в stdin, Р2).

    # ponytail: AutoAddPolicy — сервер только что провижинился через VPS Manager;
    pinning host-key появится, когда VPS Manager начнёт отдавать fingerprint.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            key_filename=key_path,
            timeout=CONNECT_TIMEOUT,
            # Только выданный per-server ключ: без этого paramiko при неудаче
            # молча пробует ssh-agent и ~/.ssh/id_* пользователя процесса.
            allow_agent=False,
            look_for_keys=False,
        )
        stdin, stdout, stderr = client.exec_command('chpasswd', timeout=EXEC_TIMEOUT)
        stdin.write(f'{username}:{new_password}\n')
        # flush обязателен: BufferedFile буферизует запись, и без него данные
        # могут не уйти до shutdown_write — chpasswd получит пустой stdin.
        stdin.flush()
        stdin.channel.shutdown_write()

        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            raise RotateError(stderr.read().decode(errors='replace'))
    finally:
        client.close()

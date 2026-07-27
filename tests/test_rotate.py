"""Тесты app/services/rotate.py (Track C, срез A3.2).

Мокаем paramiko.SSHClient — на реальные серверы не ходим.
"""
from __future__ import annotations

import string
from unittest.mock import MagicMock, patch

import pytest

from app.services.rotate import RotateError, generate_password, rotate_root


class TestGeneratePassword:
    """Р5: 24 символа, алфавит без `:`, пробелов, кавычек, `\\`, `$`."""

    def test_length_is_24(self):
        assert len(generate_password()) == 24

    def test_excludes_dangerous_chars_over_100_generations(self):
        forbidden = set(':\'"\\$ \t\n')
        for _ in range(100):
            pw = generate_password()
            assert not (forbidden & set(pw)), pw

    def test_alphabet_is_letters_digits_and_allowed_symbols(self):
        allowed = set(string.ascii_letters + string.digits + '!#%*+-=?@^_')
        for _ in range(100):
            pw = generate_password()
            assert set(pw) <= allowed


def _mock_ssh_client(exit_status=0):
    """Собирает мок paramiko.SSHClient с заданным exit_status chpasswd."""
    client = MagicMock()
    stdin = MagicMock()
    stdout = MagicMock()
    stderr = MagicMock()
    stdout.channel.recv_exit_status.return_value = exit_status
    stderr.read.return_value = b'chpasswd: some error'
    client.exec_command.return_value = (stdin, stdout, stderr)
    return client, stdin, stdout, stderr


class TestRotateRoot:

    def test_connects_with_key_file_and_timeouts(self):
        client, *_ = _mock_ssh_client(exit_status=0)
        with patch('app.services.rotate.paramiko.SSHClient', return_value=client):
            rotate_root(
                host='198.51.100.10', port=22, key_path='/tmp/key.pem',
                username='root', new_password='S3cret!Pw',
            )

        client.connect.assert_called_once()
        _, kwargs = client.connect.call_args
        assert kwargs['hostname'] == '198.51.100.10'
        assert kwargs['port'] == 22
        assert kwargs['username'] == 'root'
        assert kwargs['key_filename'] == '/tmp/key.pem'
        assert kwargs['timeout'] == 30
        client.close.assert_called_once()

    def test_password_goes_to_stdin_not_command_line(self):
        client, stdin, stdout, stderr = _mock_ssh_client(exit_status=0)
        with patch('app.services.rotate.paramiko.SSHClient', return_value=client):
            rotate_root(
                host='198.51.100.10', port=22, key_path='/tmp/key.pem',
                username='root', new_password='S3cret!Pw',
            )

        # Пароль ушёл в stdin ...
        stdin.write.assert_called_once_with('root:S3cret!Pw\n')
        stdin.channel.shutdown_write.assert_called_once()
        # ... а не в строку команды exec_command.
        command_args, exec_kwargs = client.exec_command.call_args
        assert command_args == ('chpasswd',)
        assert 'S3cret!Pw' not in command_args[0]
        assert exec_kwargs.get('timeout') == 30

    def test_stdin_flushed_before_shutdown_write(self):
        """BufferedFile буферизует запись: без flush до shutdown_write
        chpasswd может получить пустой stdin (мок этого не увидит — проверяем
        сам порядок вызовов)."""
        client, stdin, *_ = _mock_ssh_client(exit_status=0)
        with patch('app.services.rotate.paramiko.SSHClient', return_value=client):
            rotate_root(
                host='198.51.100.10', port=22, key_path='/tmp/key.pem',
                username='root', new_password='S3cret!Pw',
            )

        names = [c[0] for c in stdin.mock_calls]
        assert 'flush' in names, 'stdin.flush() не вызван'
        assert names.index('flush') < names.index('channel.shutdown_write'), \
            'flush должен идти ДО shutdown_write'

    def test_uses_only_given_key_no_agent_no_default_keys(self):
        """Иначе paramiko при неудаче молча пробует ssh-agent и ~/.ssh/id_*
        пользователя процесса — недетерминированная аутентификация."""
        client, *_ = _mock_ssh_client(exit_status=0)
        with patch('app.services.rotate.paramiko.SSHClient', return_value=client):
            rotate_root(
                host='198.51.100.10', port=22, key_path='/tmp/key.pem',
                username='root', new_password='S3cret!Pw',
            )

        _, kwargs = client.connect.call_args
        assert kwargs['allow_agent'] is False
        assert kwargs['look_for_keys'] is False

    def test_nonzero_exit_status_raises_rotate_error(self):
        client, *_ = _mock_ssh_client(exit_status=1)
        with patch('app.services.rotate.paramiko.SSHClient', return_value=client):
            with pytest.raises(RotateError):
                rotate_root(
                    host='198.51.100.10', port=22, key_path='/tmp/key.pem',
                    username='root', new_password='S3cret!Pw',
                )
        client.close.assert_called_once()


if __name__ == '__main__':
    # ponytail: минимальный self-check без pytest (см. tdd-правило про non-trivial logic).
    for _ in range(100):
        pw = generate_password()
        assert len(pw) == 24
        assert not (set(':\'"\\$ \t\n') & set(pw))
    print('rotate.py self-check OK')

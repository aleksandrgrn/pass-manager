"""Ping и traceroute до сервера из списка — с машины, где работает приложение.

Вывод отдаётся построчно, пока команда идёт, а в конце — короткая сводка.
Лимит одновременных проверок держится на flock, а не в памяти: у gunicorn
несколько процессов, и счётчик в памяти у каждого был бы свой. Блокировку
файла ядро снимает само, когда процесс умирает, — «застрявших» слотов не бывает.
"""
from __future__ import annotations

import fcntl
import ipaddress
import os
import re
import subprocess  # nosec B404 — argv списком, без shell, адрес проверен ipaddress
import threading
from collections.abc import Iterator

# Живая проверка держит поток gunicorn всё время работы, а потоков на всё
# приложение около восьми. Три оставляют остальным запас.
MAX_CONCURRENT = 3

TOOLS = ('ping', 'traceroute')

# Худший случай ping: 4 пакета по 2 с ожидания; traceroute: 20 хопов по 1 с.
# Таймаут — страховка сверх этого, а не рабочий предел.
TIMEOUTS = {'ping': 15, 'traceroute': 40}


class BusyError(Exception):
    """Слот не получен. message — что показать человеку."""


def parse_ip(value: str | None):
    """Адрес из карточки сервера или None, если там не IP."""
    try:
        return ipaddress.ip_address((value or '').strip())
    except ValueError:
        return None


def build_command(tool: str, ip) -> list[str]:
    family = f'-{ip.version}'
    if tool == 'ping':
        return ['ping', family, '-c', '4', '-W', '2', str(ip)]
    return ['traceroute', family, '-n', '-q', '1', '-w', '1', '-m', '20', str(ip)]


class Slots:
    """Слот пользователя и общий слот. release() снимает оба, повторно — без вреда."""

    def __init__(self, lock_dir: str, user_id: int):
        os.makedirs(lock_dir, exist_ok=True)
        self._files = []
        try:
            user_file = self._try_lock(os.path.join(lock_dir, f'user-{user_id}.lock'))
            if user_file is None:
                raise BusyError('У вас уже идёт проверка — дождитесь её окончания.')
            self._files.append(user_file)
            for i in range(MAX_CONCURRENT):
                slot = self._try_lock(os.path.join(lock_dir, f'slot-{i}.lock'))
                if slot is not None:
                    self._files.append(slot)
                    return
            raise BusyError('Сейчас идёт много проверок — повторите через несколько секунд.')
        except BaseException:
            self.release()
            raise

    @staticmethod
    def _try_lock(path: str):
        f = open(path, 'a')  # noqa: SIM115 — держим открытым, пока держим блокировку
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            f.close()
            return None
        return f

    def release(self) -> None:
        for f in self._files:
            f.close()
        self._files = []


def run(argv: list[str], timeout: float) -> Iterator[str]:
    """Строки вывода команды по мере появления.

    Процесс убивается по таймауту и при закрытии генератора — это случай,
    когда человек закрыл окно и сервер не смог дописать ему ответ.
    Последней строкой при таймауте идёт пометка о нём.
    """
    proc = subprocess.Popen(  # nosec B603
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    timed_out = threading.Event()

    def _kill():
        timed_out.set()
        proc.kill()

    timer = threading.Timer(timeout, _kill)
    timer.start()
    try:
        for line in proc.stdout:
            yield line.rstrip('\n')
        proc.wait()
        if timed_out.is_set():
            yield f'[прервано: дольше {timeout:g} с]'
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()


_PING_STATS = re.compile(r'(\d+) packets transmitted, (\d+) received.*?([\d.]+)% packet loss')
_PING_RTT = re.compile(r'= [\d.]+/([\d.]+)/')
_HOP = re.compile(r'^\s*(\d+)\s+(.*)$')


def summarize(tool: str, ip: str, lines: list[str]) -> dict[str, str]:
    """Сводка по выводу: level (ok/warn/bad), title, detail."""
    text = '\n'.join(lines)
    if tool == 'ping':
        stats = _PING_STATS.search(text)
        if not stats:
            return {'level': 'bad', 'title': 'Ping не выполнился', 'detail': 'смотрите вывод'}
        sent, received, loss = int(stats[1]), int(stats[2]), stats[3]
        rtt = _PING_RTT.search(text)
        avg_ms = float(rtt[1]) if rtt else None
        avg = '' if avg_ms is None else (
            f' · в среднем {avg_ms:.0f} мс' if avg_ms >= 1 else ' · в среднем <1 мс')
        if received == 0:
            return {'level': 'bad', 'title': 'Не отвечает',
                    'detail': f'потери {loss}% · 0 из {sent} пакетов'}
        if received < sent:
            return {'level': 'warn', 'title': 'Отвечает с потерями',
                    'detail': f'потери {loss}%{avg}'}
        return {'level': 'ok', 'title': 'Отвечает', 'detail': f'потери 0%{avg}'}

    last_hop, last_addr, hops = None, None, 0
    for line in lines:
        m = _HOP.match(line)
        if not m:
            continue
        hops = int(m[1])
        addr = parse_ip(m[2].split()[0]) if m[2].split() else None
        if addr is None:
            continue
        if str(addr) == ip:
            return {'level': 'ok', 'title': 'Маршрут до сервера есть',
                    'detail': f'дошёл, хопов: {hops}'}
        last_hop, last_addr = hops, str(addr)
    if hops == 0:
        return {'level': 'bad', 'title': 'Traceroute не выполнился', 'detail': 'смотрите вывод'}
    # Звёздочки значат только «не ответил»: многие узлы и сами VPS глушат пробы
    # traceroute, и исправный маршрут выглядит так же. Поэтому не «обрыв», а
    # «не подтвердился», и жёлтым — точный ответ о доступности даёт ping.
    title = 'Сервер на traceroute не ответил'
    if last_addr is None:
        return {'level': 'warn', 'title': title,
                'detail': 'не ответил ни один узел — проверьте ping'}
    return {'level': 'warn', 'title': title,
            'detail': f'последний ответивший узел — хоп {last_hop} ({last_addr}); '
                      'дальше обрыв или узлы не отвечают, проверьте ping'}

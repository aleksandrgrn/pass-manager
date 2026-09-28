"""Ping/traceroute из списка серверов: сводки, лимит, процесс, маршрут."""
from __future__ import annotations

import ipaddress
import json
import os
import sys
import time

import pytest

from app.services import netcheck

PING_OK = """PING 192.0.2.10 (192.0.2.10) 56(84) bytes of data.
64 bytes from 192.0.2.10: icmp_seq=1 ttl=54 time=34.2 ms

--- 192.0.2.10 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 33.912/34.300/35.100/0.476 ms"""

PING_LOSS = """--- 192.0.2.10 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 3004ms
rtt min/avg/max/mdev = 33.912/40.600/35.100/0.476 ms"""

PING_DEAD = """--- 192.0.2.10 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3062ms"""

TRACE_OK = """traceroute to 192.0.2.10 (192.0.2.10), 20 hops max, 60 byte packets
 1  10.0.0.1  0.412 ms
 2  *
 3  192.0.2.10  34.118 ms"""

TRACE_BROKEN = """traceroute to 192.0.2.10 (192.0.2.10), 20 hops max, 60 byte packets
 1  10.0.0.1  0.398 ms
 2  198.51.100.1  44.871 ms
 3  *
 4  *"""

TRACE_SILENT = """traceroute to 192.0.2.10 (192.0.2.10), 20 hops max, 60 byte packets
 1  *
 2  *"""


@pytest.mark.parametrize('text, level, title, detail_part', [
    (PING_OK, 'ok', 'Отвечает', 'в среднем 34 мс'),
    (PING_LOSS, 'warn', 'Отвечает с потерями', 'потери 25%'),
    (PING_DEAD, 'bad', 'Не отвечает', '0 из 4'),
    (PING_OK.replace('/34.300/', '/0.026/'), 'ok', 'Отвечает', 'в среднем <1 мс'),
    ('ping: connect: Network is unreachable', 'bad', 'Ping не выполнился', ''),
])
def test_summarize_ping(text, level, title, detail_part):
    s = netcheck.summarize('ping', '192.0.2.10', text.splitlines())
    assert (s['level'], s['title']) == (level, title)
    assert detail_part in s['detail']


@pytest.mark.parametrize('text, level, title, detail_part', [
    (TRACE_OK, 'ok', 'Маршрут до сервера есть', 'хопов: 3'),
    (TRACE_BROKEN, 'warn', 'Сервер на traceroute не ответил', 'хоп 2 (198.51.100.1)'),
    (TRACE_SILENT, 'warn', 'Сервер на traceroute не ответил', 'ни один узел'),
    ('traceroute: unknown host', 'bad', 'Traceroute не выполнился', ''),
])
def test_summarize_traceroute(text, level, title, detail_part):
    s = netcheck.summarize('traceroute', '192.0.2.10', text.splitlines())
    assert (s['level'], s['title']) == (level, title)
    assert detail_part in s['detail']


@pytest.mark.parametrize('value', [None, '', '—', '-c', 'host.example.com', '192.0.2.10; id'])
def test_parse_ip_rejects_non_ip(value):
    assert netcheck.parse_ip(value) is None


def test_build_command_follows_ip_version():
    v4 = netcheck.build_command('ping', ipaddress.ip_address('192.0.2.10'))
    v6 = netcheck.build_command('traceroute', ipaddress.ip_address('2001:db8::1'))
    assert v4[:2] == ['ping', '-4'] and v4[-1] == '192.0.2.10'
    assert v6[:2] == ['traceroute', '-6'] and v6[-1] == '2001:db8::1'


def test_slots_one_per_user(tmp_path):
    first = netcheck.Slots(str(tmp_path), user_id=1)
    with pytest.raises(netcheck.BusyError, match='уже идёт'):
        netcheck.Slots(str(tmp_path), user_id=1)
    first.release()
    netcheck.Slots(str(tmp_path), user_id=1).release()


def test_slots_global_limit(tmp_path):
    held = [netcheck.Slots(str(tmp_path), user_id=i) for i in range(netcheck.MAX_CONCURRENT)]
    with pytest.raises(netcheck.BusyError, match='много проверок'):
        netcheck.Slots(str(tmp_path), user_id=99)
    # Отказ по общему лимиту не должен оставить за собой занятый слот пользователя.
    held.pop().release()
    netcheck.Slots(str(tmp_path), user_id=99).release()
    for s in held:
        s.release()


def test_run_kills_on_timeout():
    started = time.monotonic()
    lines = list(netcheck.run(['sleep', '10'], timeout=0.5))
    assert time.monotonic() - started < 5
    assert lines == ['[прервано: дольше 0.5 с]']


def test_run_kills_process_when_client_leaves():
    script = 'import os, sys, time; print(os.getpid(), flush=True); time.sleep(30)'
    gen = netcheck.run([sys.executable, '-c', script], timeout=60)
    pid = int(next(gen))
    gen.close()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


# --------------------------------------------------------------------------- #
# Маршрут
# --------------------------------------------------------------------------- #

@pytest.fixture()
def lock_dir(app, tmp_path):
    app.config['NETCHECK_LOCK_DIR'] = str(tmp_path)
    return str(tmp_path)


@pytest.fixture()
def fake_ping(monkeypatch):
    monkeypatch.setattr(netcheck, 'build_command', lambda tool, ip: ['printf', '%s\n', PING_OK])


def _url(server_id, tool='ping'):
    return f'/servers/{server_id}/netcheck/{tool}'


def test_stream_lines_then_summary(admin_client, sample_server, lock_dir, fake_ping, admin_user):
    resp = admin_client.post(_url(sample_server.id), buffered=False)
    assert resp.status_code == 200
    assert resp.headers['X-Accel-Buffering'] == 'no'
    # Пока ответ не дочитан, слот занят — а не снят вместе с выходом из view.
    with pytest.raises(netcheck.BusyError):
        netcheck.Slots(lock_dir, admin_user.id)
    messages = [json.loads(line) for line in resp.get_data(as_text=True).splitlines()]
    resp.close()
    assert [m['line'] for m in messages[:-1]] == PING_OK.splitlines()
    assert messages[-1]['summary']['title'] == 'Отвечает'
    # Слот снят после закрытия ответа.
    netcheck.Slots(lock_dir, admin_user.id).release()


def test_busy_user_gets_429(admin_client, sample_server, lock_dir, fake_ping, admin_user):
    held = netcheck.Slots(lock_dir, admin_user.id)
    try:
        resp = admin_client.post(_url(sample_server.id))
    finally:
        held.release()
    assert resp.status_code == 429
    assert 'уже идёт' in resp.get_data(as_text=True)


@pytest.mark.parametrize('ip', [None, 'not-an-ip'])
def test_server_without_valid_ip_is_400(admin_client, sample_server, lock_dir, db, ip):
    sample_server.ip_address = ip
    db.session.commit()
    assert admin_client.post(_url(sample_server.id)).status_code == 400


def test_unknown_tool_is_404(admin_client, sample_server, lock_dir):
    assert admin_client.post(_url(sample_server.id, 'nmap')).status_code == 404


def test_invisible_server_is_403(app, groupless_admin, sample_server, lock_dir):
    from tests.conftest import login_as
    c = app.test_client()
    login_as(c, 'groupless_test')
    assert c.post(_url(sample_server.id)).status_code == 403


def test_anonymous_is_redirected(client, sample_server, lock_dir):
    assert client.post(_url(sample_server.id)).status_code == 302


def test_row_has_netcheck_button(admin_client, sample_server):
    html = admin_client.get('/servers/').get_data(as_text=True)
    assert f'data-netcheck-url="/servers/{sample_server.id}/netcheck/TOOL"' in html


@pytest.mark.parametrize('ip', [None, '—', 'host.example.com'])
def test_row_button_disabled_without_valid_ip(admin_client, sample_server, db, ip):
    sample_server.ip_address = ip
    db.session.commit()
    html = admin_client.get('/servers/').get_data(as_text=True)
    assert 'data-netcheck-url="' not in html
    assert 'нет корректного IP' in html


def test_client_leaving_kills_process(admin_client, sample_server, lock_dir, monkeypatch):
    script = 'import os, time; print(os.getpid(), flush=True); time.sleep(30)'
    monkeypatch.setattr(netcheck, 'build_command',
                        lambda tool, ip: [sys.executable, '-c', script])
    resp = admin_client.post(_url(sample_server.id), buffered=False)
    pid = int(json.loads(next(resp.response))['line'])
    resp.close()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_inline_ip_edit_refreshes_netcheck_button(admin_client, sample_server, db):
    """Кнопка в строке следует за IP, изменённым inline, без перезагрузки страницы."""
    sample_server.ip_address = None
    db.session.commit()
    html = admin_client.post(f'/servers/{sample_server.id}/field',
                             data={'field': 'ip_address', 'value': '192.0.2.7'}).get_data(as_text=True)
    assert f'id="netcheck-btn-{sample_server.id}" hx-swap-oob="true"' in html
    assert 'data-netcheck-ip="192.0.2.7"' in html


def test_inline_edit_of_other_field_leaves_button_alone(admin_client, sample_server):
    html = admin_client.post(f'/servers/{sample_server.id}/field',
                             data={'field': 'name', 'value': 'renamed'}).get_data(as_text=True)
    assert 'netcheck-btn' not in html

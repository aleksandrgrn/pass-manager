"""GRSA-163, ветка 2 этап A: смена IP/порта у подключённого сервера.

Хостер сменил машине адрес, диск прежний. Новый адрес уходит в VPS Manager
(E12), и только после его согласия сохраняется у нас. Мокаем
app.servers.views.vps_client — реального VPS Manager нет.
"""
from __future__ import annotations

import json
from unittest.mock import patch

from app.models import Server

CLIENT = 'app.servers.views.vps_client.update_server_address'


def _make_server(db, group, vps_id=42, ip='192.0.2.60', port=2233):
    server = Server(name='vps-moved-01', ip_address=ip, ssh_username='root',
                    ssh_port=port, active=True, group_id=group.id,
                    vps_manager_server_id=vps_id)
    db.session.add(server)
    db.session.commit()
    return server


def _ok(ip):
    return {'success': True, 'server': {'ip_address': ip}}


def _form(server, **overrides):
    data = {'name': server.name, 'ip_address': server.ip_address,
            'ssh_username': 'root', 'ssh_port': str(server.ssh_port), 'active': 'y'}
    data.update(overrides)
    return data


def _reload(db, server_id):
    db.session.expire_all()
    return db.session.get(Server, server_id)


class TestEditForm:

    def test_new_ip_goes_to_vps_manager_then_saved(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        with patch(CLIENT, return_value=_ok('198.51.100.7')) as mock_update:
            resp = admin_client.post(f'/servers/{server.id}/edit',
                                     data=_form(server, ip_address=' 198.51.100.7 '))

        assert resp.status_code == 302
        mock_update.assert_called_once_with(42, '198.51.100.7', 2233)
        srv = _reload(db, server.id)
        assert (srv.ip_address, srv.ssh_port, srv.vps_manager_server_id) == (
            '198.51.100.7', 2233, 42)

    def test_port_change_alone_goes_to_vps_manager(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        with patch(CLIENT, return_value=_ok('192.0.2.60')) as mock_update:
            resp = admin_client.post(f'/servers/{server.id}/edit',
                                     data=_form(server, ssh_port='22'))

        assert resp.status_code == 302
        mock_update.assert_called_once_with(42, '192.0.2.60', 22)
        assert _reload(db, server.id).ssh_port == 22

    def test_refusal_keeps_everything_and_shows_reason(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        refusal = {'success': False, 'error_type': 'connection_failed',
                   'message': 'По новому адресу не пускает ключ VPS Manager: timeout'}
        with patch(CLIENT, return_value=refusal):
            resp = admin_client.post(f'/servers/{server.id}/edit',
                                     data=_form(server, name='renamed', ip_address='198.51.100.7'))

        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'не пускает ключ VPS Manager: timeout' in body
        assert 'новую машину' in body
        srv = _reload(db, server.id)
        assert (srv.name, srv.ip_address, srv.ssh_port) == ('vps-moved-01', '192.0.2.60', 2233)

    def test_unchanged_address_does_not_call_vps_manager(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        with patch(CLIENT) as mock_update:
            resp = admin_client.post(f'/servers/{server.id}/edit',
                                     data=_form(server, name='renamed'))

        assert resp.status_code == 302
        mock_update.assert_not_called()
        assert _reload(db, server.id).name == 'renamed'

    def test_cleared_ip_is_refused_for_connected(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        with patch(CLIENT) as mock_update:
            resp = admin_client.post(f'/servers/{server.id}/edit',
                                     data=_form(server, ip_address=''))

        assert resp.status_code == 200
        mock_update.assert_not_called()
        assert _reload(db, server.id).ip_address == '192.0.2.60'

    def test_unconnected_server_saved_locally(self, admin_client, db, default_group):
        server = _make_server(db, default_group, vps_id=None)
        with patch(CLIENT) as mock_update:
            resp = admin_client.post(f'/servers/{server.id}/edit',
                                     data=_form(server, ip_address='198.51.100.7'))

        assert resp.status_code == 302
        mock_update.assert_not_called()
        assert _reload(db, server.id).ip_address == '198.51.100.7'


class TestInlineCell:

    def _post(self, client, server, field, value):
        return client.post(f'/servers/{server.id}/field',
                           data={'field': field, 'value': value},
                           headers={'HX-Request': 'true'})

    def test_new_ip_goes_to_vps_manager(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        with patch(CLIENT, return_value=_ok('198.51.100.7')) as mock_update:
            resp = self._post(admin_client, server, 'ip_address', '198.51.100.7')

        assert resp.status_code == 200
        mock_update.assert_called_once_with(42, '198.51.100.7', 2233)
        assert '198.51.100.7' in resp.get_data(as_text=True)
        assert _reload(db, server.id).ip_address == '198.51.100.7'

    def test_refusal_returns_old_cell_and_message(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        refusal = {'success': False, 'message': 'По новому адресу не пускает ключ VPS Manager: x'}
        with patch(CLIENT, return_value=refusal):
            resp = self._post(admin_client, server, 'ip_address', '198.51.100.7')

        # 200, а не 4xx: htmx 1.9 ошибочный ответ не подставляет, ячейка
        # так и осталась бы полем ввода.
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert '192.0.2.60' in body and '198.51.100.7' not in body
        trigger = json.loads(resp.headers['HX-Trigger'])
        assert 'не пускает ключ VPS Manager: x' in trigger['inlineEditError']
        # Заголовок уходит в latin-1: кириллица только \u-экранами.
        assert resp.headers['HX-Trigger'].isascii()
        assert _reload(db, server.id).ip_address == '192.0.2.60'

    def test_other_field_does_not_call_vps_manager(self, admin_client, db, default_group):
        server = _make_server(db, default_group)
        with patch(CLIENT) as mock_update:
            resp = self._post(admin_client, server, 'name', 'renamed')

        assert resp.status_code == 200
        mock_update.assert_not_called()


def test_client_calls_e12(app):
    from unittest.mock import MagicMock

    from app.services import vps_client

    app.config['VPS_MANAGER_API_URL'] = 'http://127.0.0.1:5000/api/svc'
    response = MagicMock(status_code=200)
    response.json.return_value = {'success': True}
    with app.app_context(), patch('app.services.vps_client.requests.request',
                                  return_value=response) as mock_req:
        vps_client.update_server_address(42, '198.51.100.7', 22)

    args, kwargs = mock_req.call_args
    assert args == ('POST', 'http://127.0.0.1:5000/api/svc/servers/42/address')
    assert kwargs['json'] == {'ip_address': '198.51.100.7', 'ssh_port': 22}
    # Проверка связи по SSH в VPS Manager дольше стандартных 30 с.
    assert kwargs['timeout'] >= 90

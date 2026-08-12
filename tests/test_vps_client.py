"""Тесты для app/services/vps_client.py — тонкий HTTP-клиент /api/svc.

Мокаем requests.request (monkeypatch), проверяем: заголовки (Bearer, job-id),
маппинг E1-E8 на пути/методы, и обработку connection-refused/5xx/невалидного
JSON в единый {"success": False, "error_type": ..., "message": ...}.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from app.services import vps_client


@pytest.fixture()
def configured_app(app):
    app.config["VPS_MANAGER_API_URL"] = "http://127.0.0.1:5000/api/svc"
    app.config["VPS_MANAGER_SERVICE_TOKEN"] = "test-token-xyz"
    return app


def _mock_response(json_data=None, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {"success": True}
    return resp


class TestHeadersAndTransport:
    def test_add_server_sends_bearer_and_payload(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response({"success": True, "server_id": 1})

            result = vps_client.add_server(
                name="srv",
                ip_address="192.0.2.1",
                ssh_port=22,
                username="root",
                password="pw",
                bootstrap_request_id="req-1",
            )

        assert result["success"] is True
        args, kwargs = mock_req.call_args
        assert args[0] == "POST"
        assert args[1] == "http://127.0.0.1:5000/api/svc/servers/add"
        assert kwargs["headers"]["Authorization"] == "Bearer test-token-xyz"
        assert kwargs["json"]["bootstrap_request_id"] == "req-1"
        assert kwargs["timeout"] == vps_client.DEFAULT_TIMEOUT

    def test_job_id_sent_as_header_when_provided(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response()
            vps_client.list_servers(job_id="job-42")

        _, kwargs = mock_req.call_args
        assert kwargs["headers"]["X-Pass-Manager-Job-Id"] == "job-42"

    def test_no_job_id_header_when_not_provided(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response()
            vps_client.list_servers()

        _, kwargs = mock_req.call_args
        assert "X-Pass-Manager-Job-Id" not in kwargs["headers"]


class TestEndpointMapping:
    def test_list_keys_get_with_name_param(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response({"success": True, "keys": []})
            vps_client.list_keys(name="frag")

        args, kwargs = mock_req.call_args
        assert args[0] == "GET"
        assert args[1].endswith("/keys")
        assert kwargs["params"] == {"name": "frag"}

    def test_generate_key_post(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response({"success": True, "id": 5})
            result = vps_client.generate_key(name="Ivanov", key_type="rsa")

        assert result["success"] is True
        args, kwargs = mock_req.call_args
        assert args[0] == "POST"
        assert args[1].endswith("/keys/generate")
        assert kwargs["json"] == {"name": "Ivanov", "key_type": "rsa"}

    def test_deploy_key_post(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response()
            vps_client.deploy_key(key_id=1, server_id=2)

        args, kwargs = mock_req.call_args
        assert args[1].endswith("/keys/deploy")
        assert kwargs["json"] == {"key_id": 1, "server_id": 2}

    def test_revoke_deployment_post(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response()
            vps_client.revoke_deployment(key_id=1, server_id=2)

        args, kwargs = mock_req.call_args
        assert args[1].endswith("/key-deployments/revoke")
        assert kwargs["json"] == {"key_id": 1, "server_id": 2}

    def test_revoke_key_all_post_path_param(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response()
            vps_client.revoke_key_all(key_id=7)

        args, kwargs = mock_req.call_args
        assert args[0] == "POST"
        assert args[1].endswith("/keys/revoke-all/7")

    def test_test_server_post_path_param(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response()
            vps_client.test_server(server_id=9)

        args, kwargs = mock_req.call_args
        assert args[0] == "POST"
        assert args[1].endswith("/servers/test/9")

    def test_get_access_key_get_path_param(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response({"success": True, "private_key": "pem"})
            result = vps_client.get_access_key(server_id=3)

        assert result["private_key"] == "pem"
        args, kwargs = mock_req.call_args
        assert args[0] == "GET"
        assert args[1].endswith("/servers/3/access-key")

    def test_get_private_key_get_path_param(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response({"success": True, "private_key": "pem"})
            result = vps_client.get_private_key(key_id=7)

        assert result["private_key"] == "pem"
        args, kwargs = mock_req.call_args
        assert args[0] == "GET"
        assert args[1].endswith("/keys/7/private")
        assert kwargs["headers"]["Authorization"] == "Bearer test-token-xyz"

    def test_list_key_deployments_get_path_and_bearer(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response({"success": True, "deployments": []})
            vps_client.list_key_deployments()

        args, kwargs = mock_req.call_args
        assert args[0] == "GET"
        assert args[1].endswith("/key-deployments")
        assert kwargs["headers"]["Authorization"] == "Bearer test-token-xyz"

    def test_list_key_deployments_returns_response_as_is(self, configured_app):
        payload = {
            "success": True,
            "deployments": [{"key_id": 1, "server_id": 2, "deployed_at": "..."}],
        }
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response(payload)
            result = vps_client.list_key_deployments()

        assert result == payload

    def test_list_key_deployments_forwards_job_id_header(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response()
            vps_client.list_key_deployments(job_id="job-77")

        _, kwargs = mock_req.call_args
        assert kwargs["headers"]["X-Pass-Manager-Job-Id"] == "job-77"


class TestErrorHandling:
    def test_connection_refused_returns_provisioning_failed_shape(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.side_effect = requests.exceptions.ConnectionError("refused")
            result = vps_client.list_servers()

        assert result["success"] is False
        assert result["error_type"] == "connection_refused"

    def test_timeout_returns_error_shape(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.side_effect = requests.exceptions.Timeout("timed out")
            result = vps_client.list_servers()

        assert result["success"] is False
        assert result["error_type"] == "timeout"

    def test_5xx_returns_server_error_shape(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response(status_code=502)
            result = vps_client.list_servers()

        assert result["success"] is False
        assert result["error_type"] == "server_error"

    def test_invalid_json_returns_invalid_response_shape(self, configured_app):
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.side_effect = ValueError("not json")
            mock_req.return_value = resp
            result = vps_client.list_servers()

        assert result["success"] is False
        assert result["error_type"] == "invalid_response"

    def test_404_passes_through_json_body(self, configured_app):
        # 4xx — не серверная ошибка, просто прокидываем JSON тела ответа как есть
        # (напр. E8 access-key на чужом сервере -> 404 {"success": False, ...}).
        with configured_app.app_context(), patch(
            "app.services.vps_client.requests.request"
        ) as mock_req:
            mock_req.return_value = _mock_response(
                {"success": False, "message": "Сервер не найден"}, status_code=404
            )
            result = vps_client.get_access_key(server_id=999)

        assert result["success"] is False
        assert result["message"] == "Сервер не найден"

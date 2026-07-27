"""Тонкий HTTP-клиент к /api/svc VPS Manager (Track C, срез A2).

Только транспорт: Bearer-токен, timeout, обработка connection-refused/5xx.
Никакой бизнес-логики онбординга — это A3. Каждая функция 1:1 к endpoint'у
E1-E8 из specs/track-c-architecture.md §4.2.

Возврат при ошибке — везде единый формат:
    {"success": False, "error_type": "...", "message": "..."}
чтобы вызывающий код (pipeline онбординга, A3) мог пометить сервер
provisioning_failed, не падая с исключением (см. §4.4).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests
from flask import current_app

DEFAULT_TIMEOUT = 30


def _headers(job_id: Optional[str] = None) -> Dict[str, str]:
    token = current_app.config.get("VPS_MANAGER_SERVICE_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"}
    if job_id:
        headers["X-Pass-Manager-Job-Id"] = job_id
    return headers


def _request(method: str, path: str, job_id: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
    base_url = current_app.config.get("VPS_MANAGER_API_URL", "")
    url = f"{base_url}{path}"

    try:
        response = requests.request(
            method, url, headers=_headers(job_id), timeout=DEFAULT_TIMEOUT, **kwargs
        )
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "error_type": "connection_refused",
            "message": f"VPS Manager недоступен: {url}",
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error_type": "timeout",
            "message": f"VPS Manager не ответил вовремя: {url}",
        }
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "error_type": "request_error",
            "message": str(e),
        }

    if response.status_code >= 500:
        return {
            "success": False,
            "error_type": "server_error",
            "message": f"VPS Manager вернул {response.status_code}",
        }

    try:
        return response.json()
    except ValueError:
        return {
            "success": False,
            "error_type": "invalid_response",
            "message": f"VPS Manager вернул не-JSON ответ ({response.status_code})",
        }


# --------------------------------------------------------------------------- #
# E1-E8
# --------------------------------------------------------------------------- #

def add_server(
    name: str,
    ip_address: str,
    ssh_port: int,
    username: str,
    password: str,
    bootstrap_request_id: str,
    category_ids: Optional[List[int]] = None,
    job_id: Optional[str] = None,
) -> Dict[str, Any]:
    payload = {
        "name": name,
        "ip_address": ip_address,
        "ssh_port": ssh_port,
        "username": username,
        "password": password,
        "bootstrap_request_id": bootstrap_request_id,
    }
    if category_ids is not None:
        payload["category_ids"] = category_ids
    return _request("POST", "/servers/add", job_id=job_id, json=payload)


def list_keys(name: Optional[str] = None, job_id: Optional[str] = None) -> Dict[str, Any]:
    params = {"name": name} if name else None
    return _request("GET", "/keys", job_id=job_id, params=params)


def generate_key(
    name: str, key_type: str, description: Optional[str] = None, job_id: Optional[str] = None
) -> Dict[str, Any]:
    payload = {"name": name, "key_type": key_type}
    if description is not None:
        payload["description"] = description
    return _request("POST", "/keys/generate", job_id=job_id, json=payload)


def deploy_key(key_id: int, server_id: int, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _request(
        "POST", "/keys/deploy", job_id=job_id, json={"key_id": key_id, "server_id": server_id}
    )


def revoke_deployment(key_id: int, server_id: int, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _request(
        "POST",
        "/key-deployments/revoke",
        job_id=job_id,
        json={"key_id": key_id, "server_id": server_id},
    )


def revoke_key_all(key_id: int, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _request("POST", f"/keys/revoke-all/{key_id}", job_id=job_id)


def list_servers(name: Optional[str] = None, job_id: Optional[str] = None) -> Dict[str, Any]:
    params = {"name": name} if name else None
    return _request("GET", "/servers", job_id=job_id, params=params)


def test_server(server_id: int, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _request("POST", f"/servers/test/{server_id}", job_id=job_id)


def get_access_key(server_id: int, job_id: Optional[str] = None) -> Dict[str, Any]:
    return _request("GET", f"/servers/{server_id}/access-key", job_id=job_id)

"""Pipeline автоматического онбординга сервера (Track C, срез A3.1).

Р1 (specs/track-c-plan-A3.md): транзиентный bootstrap-cred хранится в
`ProvisioningJob.steps_json` зашифрованным Fernet (`app.security.encrypt`),
а НЕ в памяти процесса — prod gunicorn `-w 4`, browser-driven polling может
попасть в произвольный воркер, который не увидит in-memory dict другого.
Стирается сразу после успеха шага bootstrap.

Шаги `fetch_key`/`rotate`/`promote` реализованы в A3.2 (specs/track-c-plan-A3.md,
Фаза A3.2): забрать per-server root-ключ (E8), сменить root-пароль по
write-ahead pattern (§5.3), promote.

FIX-6c (A3.3, app-lock): один активный job онбординга на сервер — проверка в
`start_onboarding` + защита от гонки двух одновременных поллингов внутри
`run_next_step` (шаг помечается 'running' до исполнения).
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from flask import current_app

from app.extensions import db
from app.models import ProvisioningJob, Server
from app.security import decrypt, encrypt
from app.services import vps_client
from app.services.rotate import generate_password, rotate_root

# Упорядоченный список шагов pipeline'а (specs/track-c-plan-A3.md, Фаза A3.1 п.5).
STEPS = ['catalog', 'bootstrap', 'fetch_key', 'rotate', 'promote']

_TERMINAL_JOB_STATUSES = ('success', 'failed', 'cancelled')
_DONE_STEP_STATUSES = ('done', 'skipped')
_ACTIVE_JOB_STATUSES = ('pending', 'running')


class OnboardingLockedError(Exception):
    """У сервера уже есть активный job онбординга (FIX-6c, app-lock)."""


def start_onboarding(server: Server, user, bootstrap_password: str) -> ProvisioningJob:
    """Создаёт job онбординга, переводит сервер в provisioning.

    bootstrap_password кладётся в steps_json зашифрованным (Р1) и стирается
    оттуда в шаге bootstrap сразу после успеха (см. `_step_bootstrap`).

    FIX-6c: один активный job на сервер — если уже есть job со
    status in ('pending', 'running'), отказываем.
    """
    existing = ProvisioningJob.query.filter(
        ProvisioningJob.server_id == server.id,
        ProvisioningJob.status.in_(_ACTIVE_JOB_STATUSES),
    ).first()
    if existing is not None:
        raise OnboardingLockedError(
            f'У сервера #{server.id} уже есть активный job онбординга (#{existing.id})',
        )

    state = {
        'steps': {step_id: 'pending' for step_id in STEPS},
        'bootstrap_cred': encrypt(bootstrap_password),
    }
    job = ProvisioningJob(
        server_id=server.id,
        initiated_by=user.id,
        job_type='onboarding',
        status='running',
        steps_json=json.dumps(state),
    )
    db.session.add(job)

    server.provisioning_status = 'provisioning'
    server.bootstrap_request_id = uuid.uuid4().hex

    db.session.commit()
    return job


def run_next_step(job: ProvisioningJob) -> Dict[str, str]:
    """Находит первый невыполненный шаг и исполняет ровно один.

    Возвращает актуальное состояние шагов ({step_id: status}) для рендера.
    Если job уже в терминальном статусе или все шаги выполнены — no-op.

    FIX-6c: гонка двух одновременных поллингов. Шаг помечается 'running' и
    коммитится ДО исполнения; если он уже 'running' (другой поллинг успел
    первым), выходим без повторного запуска. Каждый обработчик шага всегда
    завершает его в 'done'/'failed' (см. _STEP_HANDLERS), поэтому 'running'
    не залипает.
    """
    state = json.loads(job.steps_json) if job.steps_json else {'steps': {}}
    steps_state = state.setdefault('steps', {})

    if job.status not in _TERMINAL_JOB_STATUSES:
        next_step = next(
            (s for s in STEPS if steps_state.get(s) not in _DONE_STEP_STATUSES), None,
        )
        if next_step is not None:
            if steps_state.get(next_step) == 'running':
                # Другой поллинг уже исполняет этот шаг — выходим без повтора.
                return dict(steps_state)

            steps_state[next_step] = 'running'
            job.steps_json = json.dumps(state)
            db.session.commit()  # коммит 'running' ДО исполнения — видим гонку
            # ponytail: check-then-set, не атомарный UPDATE ... WHERE — окно
            # между чтением и этим коммитом теоретически возможно при истинно
            # одновременной записи. Апгрейд при необходимости: атомарный
            # UPDATE steps_json ... WHERE status != 'running' (compare-and-swap).

            _STEP_HANDLERS[next_step](job, state)
            job.steps_json = json.dumps(state)
            db.session.commit()

        # Все шаги пройдены — закрываем job. Без этого job навсегда остаётся
        # 'running', а modal останавливает HTMX-поллинг именно по терминальному
        # статусу job'а → бесконечный цикл запросов.
        if job.status not in _TERMINAL_JOB_STATUSES and all(
            steps_state.get(s) in _DONE_STEP_STATUSES for s in STEPS
        ):
            job.status = 'success'
            job.finished_at = datetime.now(timezone.utc)
            db.session.commit()

    return dict(state['steps'])


def restart_job(job: ProvisioningJob) -> None:
    """Restart pipeline (план A3.3 п.3): переиспользует существующий job.

    Сбрасывает в 'pending' первый незавершённый шаг — успешные шаги (в steps_json)
    не трогаем. Дальше обычный поллинг подхватит job с этого шага.

    Сбрасывается не только 'failed', но и 'running': если воркер умер между
    коммитом 'running' и коммитом результата, шаг залипает — повторный поллинг
    видит 'running' и выходит, job навсегда остаётся незавершённым. Restart —
    единственный выход из этого состояния. Все шаги идемпотентны (E1 по
    bootstrap_request_id, fetch_key перезаписывает файл, rotate переиспользует
    password_pending), поэтому повторный прогон безопасен.
    """
    state = json.loads(job.steps_json) if job.steps_json else {'steps': {}}
    steps_state = state.setdefault('steps', {})

    stuck_step = next(
        (s for s in STEPS if steps_state.get(s) not in _DONE_STEP_STATUSES), None,
    )
    if stuck_step is not None:
        steps_state[stuck_step] = 'pending'

    job.steps_json = json.dumps(state)
    job.status = 'running'
    job.error_message = None
    job.finished_at = None

    server = db.session.get(Server, job.server_id)
    server.provisioning_status = 'provisioning'

    db.session.commit()


def _step_catalog(job: ProvisioningJob, state: Dict[str, Any]) -> None:
    """no-op: запись сервера уже создана в start_onboarding."""
    state['steps']['catalog'] = 'done'


def _step_bootstrap(job: ProvisioningJob, state: Dict[str, Any]) -> None:
    """E1 (`POST /servers/add`): bootstrap сервера в VPS Manager."""
    server = db.session.get(Server, job.server_id)
    bootstrap_cred = state.get('bootstrap_cred')
    password = decrypt(bootstrap_cred) if bootstrap_cred else None

    result = vps_client.add_server(
        name=server.name,
        ip_address=server.ip_address,
        ssh_port=server.ssh_port or 22,
        username=server.ssh_username,
        password=password,
        bootstrap_request_id=server.bootstrap_request_id,
    )

    if not result.get('success'):
        job.status = 'failed'
        job.error_message = result.get('message') or 'bootstrap failed'
        server.provisioning_status = 'provisioning_failed'
        state['steps']['bootstrap'] = 'failed'
        return

    server.vps_manager_server_id = result.get('server_id')
    state.pop('bootstrap_cred', None)  # Р1: стираем сразу после успеха
    state['steps']['bootstrap'] = 'done'


def _key_file_path(server_id: int) -> str:
    keys_dir = current_app.config['ANSIBLE_KEYS_DIR']
    return os.path.join(keys_dir, f'{server_id}_root.pem')


def _write_key_file(server_id: int, pem: str) -> None:
    """Пишет приватный pem с правами 0600 сразу при создании (FIX-2, план A3.2 п.3).

    `os.open(..., 0o600)` вместо `chmod` после записи — иначе есть окно, когда
    приватный ключ читаем всеми. Директория — 0700.
    """
    keys_dir = current_app.config['ANSIBLE_KEYS_DIR']
    if not os.path.isdir(keys_dir):
        os.makedirs(keys_dir, mode=0o700, exist_ok=True)

    fd = os.open(_key_file_path(server_id), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem.encode('utf-8'))
    finally:
        os.close(fd)


def _step_fetch_key(job: ProvisioningJob, state: Dict[str, Any]) -> None:
    """E8 (`GET /servers/<id>/access-key`): забрать per-server root-ключ на ФС."""
    server = db.session.get(Server, job.server_id)
    result = vps_client.get_access_key(server.vps_manager_server_id)

    if not result.get('success'):
        job.status = 'failed'
        job.error_message = 'key_fetch_failed: ' + (result.get('message') or '')
        server.provisioning_status = 'provisioning_failed'
        state['steps']['fetch_key'] = 'failed'
        return

    _write_key_file(server.id, result['private_key'])
    state['steps']['fetch_key'] = 'done'


def _step_rotate(job: ProvisioningJob, state: Dict[str, Any]) -> None:
    """Write-ahead (specs/track-c-plan-A3.md, Фаза A3.2 п.5, §5.3):

    1. Генерируем новый пароль (если ещё не сгенерирован — retry его переиспользует).
    2. Пишем в `server.password_pending` и коммитим — ДО SSH.
    3. Выполняем chpasswd по per-server root-ключу.

    При падении на шаге 3 `password_pending` НЕ стирается — это страховка
    (loss-window = 0), promote в неё превратит следующий успешный retry.
    """
    server = db.session.get(Server, job.server_id)

    if not server.password_pending:
        server.password_pending = generate_password()
        db.session.commit()  # write-ahead: коммит ДО SSH, порядок нерушим

    try:
        rotate_root(
            host=server.ip_address,
            port=server.ssh_port or 22,
            key_path=_key_file_path(server.id),
            username='root',
            new_password=server.password_pending,
        )
    except Exception as exc:
        job.status = 'failed'
        job.error_message = f'rotate_failed: {exc}'
        server.provisioning_status = 'provisioning_failed'
        state['steps']['rotate'] = 'failed'
        return

    state['steps']['rotate'] = 'done'


def _step_promote(job: ProvisioningJob, state: Dict[str, Any]) -> None:
    """Переносит password_pending в password. Закрытие job — забота run_next_step."""
    server = db.session.get(Server, job.server_id)
    server.password = server.password_pending
    server.password_pending = None
    server.provisioning_status = 'ready'
    state['steps']['promote'] = 'done'


_STEP_HANDLERS = {
    'catalog': _step_catalog,
    'bootstrap': _step_bootstrap,
    'fetch_key': _step_fetch_key,
    'rotate': _step_rotate,
    'promote': _step_promote,
}

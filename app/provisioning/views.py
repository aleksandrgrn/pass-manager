"""Provisioning pipeline endpoints (Track C, срез A3.1).

Р3 (specs/track-c-plan-A3.md): путь `/provisioning/...`, не `/ansible/...` —
в A3 Ansible нет вообще, он появится в A4 со своим отдельным blueprint'ом.
"""
import json

from flask import Blueprint, abort, redirect, render_template, url_for
from flask_login import current_user, login_required

from app.access.rules import assert_can_access_server
from app.auth.decorators import role_required
from app.extensions import db
from app.models import ProvisioningJob, Server
from app.services.provisioning import STEPS, restart_job, run_next_step

provisioning_bp = Blueprint('provisioning', __name__)


def _get_job_or_403(job_id):
    """Достать job и убедиться, что его сервер доступен текущему пользователю.

    До B1 проверки здесь не было — RBAC был плоский. Но pipeline меняет root-пароль
    на живой машине, так что чужой job гонять нельзя тем более, чем чужую карточку
    смотреть. Батчевые job'ы (server_id=NULL, задел под A5) — только суперадмину.
    """
    job = ProvisioningJob.query.get_or_404(job_id)
    server = db.session.get(Server, job.server_id) if job.server_id else None
    if server is not None:
        assert_can_access_server(server)
    elif not current_user.is_superadmin:
        abort(403, description='Батчевые задачи доступны только суперадмину')
    return job


@provisioning_bp.route('/jobs/<int:job_id>', methods=['GET'])
@login_required
@role_required('admin', 'superadmin')
def job_page(job_id):
    """Страница онбординга — единственный вход на неё по GET.

    Сюда редиректят и servers.create, и restart. Раньше каждый рисовал её
    прямо в ответ на POST, из-за чего в истории браузера оставалась запись,
    уже создавшая сервер (или уже перезапустившая pipeline): F5 предлагал
    повторить отправку и повтор делал это второй раз.
    """
    job = _get_job_or_403(job_id)
    server = db.session.get(Server, job.server_id)
    steps = json.loads(job.steps_json)['steps']
    return render_template(
        'servers/_provisioning_modal.html',
        job=job, server=server, steps=steps, provisioning_steps=STEPS,
    )


@provisioning_bp.route('/jobs/<int:job_id>/step', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def run_step(job_id):
    """Исполняет один следующий шаг pipeline'а, возвращает HTML-фрагмент шагов.

    A3.3 п.1: раньше рендерился весь modal ради одного div'а (hx-select его
    вырезал). Теперь фрагмент рендерится и возвращается напрямую.
    """
    job = _get_job_or_403(job_id)
    steps = run_next_step(job)
    return render_template(
        'servers/_provisioning_steps.html',
        job=job, steps=steps, provisioning_steps=STEPS,
    )


@provisioning_bp.route('/jobs/<int:job_id>/restart', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def restart(job_id):
    """Restart pipeline после provisioning_failed (план A3.3 п.3).

    Переиспользует job, продолжает обычным поллингом — редиректит на ту же
    страницу, что и первый запуск из servers.create.
    """
    job = _get_job_or_403(job_id)
    restart_job(job)
    return redirect(url_for('provisioning.job_page', job_id=job.id))

"""Provisioning pipeline endpoints (Track C, срез A3.1).

Р3 (specs/track-c-plan-A3.md): путь `/provisioning/...`, не `/ansible/...` —
в A3 Ansible нет вообще, он появится в A4 со своим отдельным blueprint'ом.
"""
import json

from flask import Blueprint, render_template
from flask_login import login_required

from app.auth.decorators import role_required
from app.extensions import db
from app.models import ProvisioningJob, Server
from app.services.provisioning import STEPS, restart_job, run_next_step

provisioning_bp = Blueprint('provisioning', __name__)


@provisioning_bp.route('/jobs/<int:job_id>/step', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def run_step(job_id):
    """Исполняет один следующий шаг pipeline'а, возвращает HTML-фрагмент шагов.

    A3.3 п.1: раньше рендерился весь modal ради одного div'а (hx-select его
    вырезал). Теперь фрагмент рендерится и возвращается напрямую.

    Доступ к чужому job отдельно не проверяется (RBAC плоский, R1) — только
    существование job (иначе 404).
    """
    job = ProvisioningJob.query.get_or_404(job_id)
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

    Переиспользует job, продолжает обычным поллингом — отдаёт полную
    страницу modal'а (как при первом запуске из servers.create).
    """
    job = ProvisioningJob.query.get_or_404(job_id)
    restart_job(job)
    server = db.session.get(Server, job.server_id)
    steps = json.loads(job.steps_json)['steps']
    return render_template(
        'servers/_provisioning_modal.html',
        job=job, server=server, steps=steps, provisioning_steps=STEPS,
    )

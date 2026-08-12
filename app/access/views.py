"""Track C B1.3: экран управления группами для суперадмина.

Все маршруты — только суперадмин (Р7: назначение в группы и управление ими —
не для admin). Мутации возвращают HTML-фрагмент (три блока экрана) для
HTMX-подмены, а не редирект — состояние блоков «Группы»/«Без группы»/«Люди»
взаимозависимо (например, вывод из группы возвращает человека в «Без группы»),
поэтому после любой мутации проще и надёжнее перерисовать все три блока целиком.
"""
from datetime import datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required, current_user
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import ServerGroup, ServerGroupMembership, User, AccessAssignment
from app.auth.decorators import role_required
from app.services import vps_client

access_bp = Blueprint('access', __name__)


def _blocks_context(error=None):
    """Собрать данные для всех трёх блоков экрана."""
    # ponytail: число людей/серверов на группу читается в шаблоне через
    # group.memberships|length и group.servers|length — по коллекции, N+1
    # при считанных группах не страшно. Станут сотни групп — переписать на
    # один агрегирующий запрос (GROUP BY + subquery).
    groups = ServerGroup.query.order_by(ServerGroup.name).all()

    # Экран управляет группами для admin-ролей: superadmin в группах не
    # состоит и не нуждается в них (Р2 — видит всё и так), показывать его
    # в «без группы»/«люди» было бы бессмысленным шумом.
    groupless_users = (
        User.query.filter(User.role == 'admin', ~User.group_memberships.any())
        .order_by(User.username)
        .all()
    )
    member_users = (
        User.query.filter(User.role == 'admin', User.group_memberships.any())
        .order_by(User.username)
        .all()
    )
    # ponytail: то же самое N+1, но по людям — один .count() на человека.
    # Приемлемо, пока людей десятки; при сотнях — один GROUP BY по user_id.
    active_grants_by_user = {
        u.id: AccessAssignment.query.filter_by(user_id=u.id, state='active').count()
        for u in member_users
    }

    return {
        'groups': groups,
        'groupless_users': groupless_users,
        'member_users': member_users,
        'active_grants_by_user': active_grants_by_user,
        'error': error,
    }


def _render_blocks(error=None):
    return render_template('access/_blocks.html', **_blocks_context(error=error))


@access_bp.route('/')
@login_required
def index():
    # Блоки групп и людей — суперадминские; обычному сотруднику собирать их
    # незачем, он увидит только свой личный блок.
    context = _blocks_context() if current_user.is_superadmin else {}
    return render_template('access/index.html', **context)


@access_bp.route('/groups', methods=['POST'])
@login_required
@role_required('superadmin')
def create_group():
    name = (request.form.get('name') or '').strip()
    can_create_servers = request.form.get('can_create_servers') == 'on'

    if not name:
        return _render_blocks(error='Название группы обязательно'), 200

    group = ServerGroup(name=name, can_create_servers=can_create_servers)
    db.session.add(group)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _render_blocks(error=f'Группа «{name}» уже существует'), 200

    return _render_blocks()


@access_bp.route('/groups/<int:group_id>/delete', methods=['POST'])
@login_required
@role_required('superadmin')
def delete_group(group_id):
    group = ServerGroup.query.get_or_404(group_id)
    # Серверы группы не удаляются — Server.group_id (nullable FK) обнуляется
    # средствами ORM (backref без cascade), проверено test_groups_b1.py.
    db.session.delete(group)
    db.session.commit()
    return _render_blocks()


@access_bp.route('/groups/<int:group_id>/toggle-create', methods=['POST'])
@login_required
@role_required('superadmin')
def toggle_group_create(group_id):
    group = ServerGroup.query.get_or_404(group_id)
    group.can_create_servers = not group.can_create_servers
    db.session.commit()
    return _render_blocks()


@access_bp.route('/users/<int:user_id>/groups', methods=['POST'])
@login_required
@role_required('superadmin')
def add_membership(user_id):
    user = User.query.get_or_404(user_id)
    group_id = request.form.get('group_id', type=int)
    if not group_id:
        return _render_blocks(error='Группа не выбрана'), 200
    group = ServerGroup.query.get_or_404(group_id)

    membership = ServerGroupMembership(
        user_id=user.id, group_id=group.id, added_by=current_user.id,
    )
    db.session.add(membership)
    try:
        db.session.commit()
    except IntegrityError:
        # uq_user_group: повторное приписывание к той же группе — не 500.
        db.session.rollback()
        return _render_blocks(
            error=f'{user.username} уже состоит в группе «{group.name}»'
        ), 200

    return _render_blocks()


@access_bp.route('/users/<int:user_id>/groups/<int:group_id>/delete', methods=['POST'])
@login_required
@role_required('superadmin')
def remove_membership(user_id, group_id):
    membership = ServerGroupMembership.query.filter_by(
        user_id=user_id, group_id=group_id,
    ).first()
    if membership is None:
        abort(404)
    db.session.delete(membership)
    db.session.commit()
    return _render_blocks()


@access_bp.route('/key/download', methods=['POST'])
@login_required
def download_key():
    """C2: отдать приватную половину личного ключа. Ровно один раз."""
    if current_user.vps_manager_key_id is None:
        flash('Личного ключа ещё нет — он создаётся при первой выдаче доступа.', 'error')
        return redirect(url_for('access.index'))

    if current_user.key_downloaded_at is not None:
        # Одноразовость — сигнализация, а не защита: кто украл учётные данные и
        # скачал первым, ключ уже получил. Ценность в том, что законный владелец
        # увидит отказ и придёт к суперадмину, то есть кража станет заметной.
        current_app.logger.warning(
            'Повторная попытка скачать личный ключ: пользователь %s, ключ %s',
            current_user.username, current_user.vps_manager_key_id,
        )
        flash('Ключ уже скачивали. Повторная выдача — через суперадмина.', 'error')
        return redirect(url_for('access.index'))

    resp = vps_client.get_private_key(current_user.vps_manager_key_id)
    if not resp.get('success'):
        flash(f'Не удалось получить ключ: {resp.get("message")}', 'error')
        return redirect(url_for('access.index'))

    # Флаг ставится только после успешного ответа: иначе сбой на той стороне
    # сжигал бы единственную попытку человека.
    current_user.key_downloaded_at = datetime.utcnow()
    db.session.commit()

    return Response(
        resp['private_key'],
        mimetype='application/x-pem-file',
        headers={
            'Content-Disposition': f'attachment; filename=id_rsa_{current_user.username}',
        },
    )

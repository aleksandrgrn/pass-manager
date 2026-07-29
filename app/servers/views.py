"""Server CRUD + HTMX endpoints."""
import json

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    jsonify, current_app, abort
)
from flask_login import login_required, current_user
from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models import (
    Server, Domain, ProvisioningJob, ServerGroup, ServerGroupMembership,
)
from app.access.rules import assert_can_access_server, visible_servers
from app.auth.decorators import role_required
from app.servers.forms import (
    ServerForm, ServerFilterForm,
    INLINE_EDITABLE_FIELDS, INLINE_TOGGLE_FIELDS, TRANSIENT_FORM_FIELDS,
)
from app.services.provisioning import STEPS, OnboardingLockedError, start_onboarding

servers_bp = Blueprint('servers', __name__)


# Sortable columns whitelist
SORTABLE_COLUMNS = {
    'id': Server.id,
    'name': Server.name,
    'ip_address': Server.ip_address,
    'provider': Server.provider,
    'active': Server.active,
}


def _apply_filters(query, form):
    """Apply search/active filters to query."""
    q = form.q.data
    if q:
        like = f'%{q}%'
        query = query.filter(or_(
            Server.name.ilike(like),
            Server.ip_address.ilike(like),
            Server.provider.ilike(like),
            Server.notes.ilike(like),
        ))
    if form.active.data:
        query = query.filter(Server.active.is_(True))
    return query


def _passwords_visible():
    """Whether current user can see password columns."""
    return current_user.is_authenticated and current_user.can_view_passwords


NO_GROUP_CHOICE = 0


def _group_choices():
    """Варианты для поля «Группа» — зависят от того, кто заполняет форму.

    Суперадмину доступны все группы и вариант «без группы». Админу — только те
    его группы, которым разрешено заводить серверы (Р6); варианта «без группы»
    у него нет: сервер без группы видит один суперадмин, и админ, заведя такой,
    сразу потерял бы его из списка.
    """
    if current_user.is_superadmin:
        groups = ServerGroup.query.order_by(ServerGroup.name).all()
        return [(NO_GROUP_CHOICE, '— без группы —')] + [(g.id, g.name) for g in groups]

    groups = (
        ServerGroup.query
        .join(ServerGroupMembership, ServerGroupMembership.group_id == ServerGroup.id)
        .filter(
            ServerGroupMembership.user_id == current_user.id,
            ServerGroup.can_create_servers.is_(True),
        )
        .order_by(ServerGroup.name)
        .all()
    )
    return [(g.id, g.name) for g in groups]


def _get_server_or_403(server_id):
    """Достать сервер и убедиться, что он доступен текущему пользователю.

    Отдельный хелпер, а не пара строк в каждом обработчике: server-scoped
    маршрутов уже шесть, и забыть проверку в седьмом — вопрос времени.
    """
    server = Server.query.get_or_404(server_id)
    assert_can_access_server(server)
    return server


@servers_bp.route('/')
@login_required
def list_servers():
    """Main table page."""
    form = ServerFilterForm(request.args)
    sort = request.args.get('sort', 'id')
    direction = request.args.get('dir', 'asc')

    query = visible_servers(current_user)
    query = _apply_filters(query, form)

    # Sorting with whitelist
    column = SORTABLE_COLUMNS.get(sort, Server.id)
    query = query.order_by(column.desc() if direction == 'desc' else column.asc())

    page = request.args.get('page', 1, type=int)
    per_page = current_app.config.get('ITEMS_PER_PAGE', 50)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    servers = pagination.items

    # B1.4: пустой список у человека без единой группы — не поломка, а следствие
    # того, что ему ещё не выдали доступ. Отдельное сообщение вместо «Нет записей».
    no_group_access = (
        not current_user.is_superadmin and not current_user.group_memberships
    )

    return render_template(
        'servers/list.html',
        servers=servers,
        pagination=pagination,
        filter_form=form,
        sort=sort,
        direction=direction,
        passwords_visible=_passwords_visible(),
        no_group_access=no_group_access,
    )


@servers_bp.route('/<int:server_id>')
@login_required
def detail(server_id):
    """Server detail (HTML fragment for HTMX swap or full page)."""
    server = _get_server_or_403(server_id)
    domains = server.domains.all()
    # Track C A3.3 п.4: последний job нужен для error_message + кнопки Restart.
    provisioning_job = (
        ProvisioningJob.query
        .filter_by(server_id=server.id)
        .order_by(ProvisioningJob.id.desc())
        .first()
    )
    return render_template(
        'servers/detail.html',
        server=server,
        domains=domains,
        passwords_visible=_passwords_visible(),
        provisioning_job=provisioning_job,
    )


@servers_bp.route('/new', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'superadmin')
def create():
    """Add a new server. Available to all authenticated users."""
    form = ServerForm()
    form.group_id.choices = _group_choices()
    if not form.group_id.choices:
        # Р6: возможность заводить серверы — свойство группы. Ни одной подходящей
        # группы нет → и заводить некуда, форму показывать бессмысленно.
        abort(403, description='Ни одна из ваших групп не может заводить серверы')

    if form.validate_on_submit():
        do_onboarding = form.do_onboarding.data
        bootstrap_password = form.bootstrap_password.data
        # Track C A3 (Р4): транзиентные поля не должны попасть в модель через
        # populate_obj — исключаем их из формы перед вызовом.
        for field_name in TRANSIENT_FORM_FIELDS:
            del form[field_name]

        server = Server()
        form.populate_obj(server)
        if server.group_id == NO_GROUP_CHOICE:
            server.group_id = None  # SelectField отдаёт 0, в БД это NULL
        db.session.add(server)
        db.session.commit()
        flash(f'Сервер «{server.name}» добавлен.', 'success')

        if do_onboarding:
            try:
                job = start_onboarding(server, current_user, bootstrap_password)
            except OnboardingLockedError as exc:
                # FIX-6c: не должно случаться при создании нового сервера (job
                # ещё ни одного), но start_onboarding — общая точка входа.
                flash(str(exc), 'error')
                return redirect(url_for('servers.detail', server_id=server.id))
            steps = json.loads(job.steps_json)['steps']
            return render_template(
                'servers/_provisioning_modal.html',
                job=job, server=server, steps=steps, provisioning_steps=STEPS,
            )

        return redirect(url_for('servers.list_servers'))
    return render_template('servers/form.html', form=form, title='Новый сервер',
                           show_onboarding=True)


@servers_bp.route('/<int:server_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'superadmin')
def edit(server_id):
    """Edit a server (full form)."""
    server = _get_server_or_403(server_id)
    form = ServerForm(obj=server)
    if current_user.is_superadmin:
        form.group_id.choices = _group_choices()
    else:
        # Р7: перекладывать сервер между командами — дело суперадмина. Поле
        # убираем целиком, иначе populate_obj затрёт группу тем, что пришло.
        del form['group_id']

    if form.validate_on_submit():
        # Онбординг при редактировании не запускается, но транзиентные поля
        # всё равно исключаем — иначе populate_obj навесит их на модель.
        for field_name in TRANSIENT_FORM_FIELDS:
            del form[field_name]
        form.populate_obj(server)
        if server.group_id == NO_GROUP_CHOICE:
            server.group_id = None
        db.session.commit()
        flash(f'Сервер «{server.name}» обновлён.', 'success')
        return redirect(url_for('servers.list_servers'))
    return render_template('servers/form.html', form=form,
                           title=f'Редактирование: {server.name}',
                           show_onboarding=False)


@servers_bp.route('/<int:server_id>/delete', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def delete(server_id):
    """Delete a server."""
    server = _get_server_or_403(server_id)
    name = server.name
    db.session.delete(server)
    db.session.commit()
    flash(f'Сервер «{name}» удалён.', 'info')

    if request.headers.get('HX-Request'):
        return '', 204  # HTMX: remove row client-side
    return redirect(url_for('servers.list_servers'))


# --- HTMX inline editing endpoints ---

PASSWORD_FIELD_KEYWORDS = ('password', 'pass')


def _is_password_field(field_name):
    return any(kw in field_name.lower() for kw in PASSWORD_FIELD_KEYWORDS)


@servers_bp.route('/<int:server_id>/field', methods=['POST'])
@login_required
def edit_field(server_id):
    """Inline-edit a single text field via HTMX.

    Expected form fields: field=<name>, value=<new value>
    Returns the updated cell.
    """
    server = _get_server_or_403(server_id)
    field_name = (request.form.get('field') or '').strip()
    value = request.form.get('value', '').strip()

    attr = INLINE_EDITABLE_FIELDS.get(field_name)
    if not attr:
        abort(400, description='Недопустимое поле для редактирования')

    # FIX-6b: metadata доступна admin+, password-поля — только superadmin
    if _is_password_field(field_name):
        if not current_user.is_superadmin:
            abort(403, description='Недостаточно прав для редактирования пароля')
    else:
        if not current_user.is_admin:
            abort(403, description='Только просмотр: нет прав на редактирование')

    setattr(server, attr, value or None)
    db.session.commit()

    return render_template(
        'servers/_cell.html',
        server=server,
        field=field_name,
        value=value,
        passwords_visible=_passwords_visible(),
    )


@servers_bp.route('/<int:server_id>/toggle', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def toggle_field(server_id):
    """Toggle a boolean field (services, active) via HTMX."""
    server = _get_server_or_403(server_id)
    field_name = (request.form.get('field') or '').strip()

    attr = INLINE_TOGGLE_FIELDS.get(field_name)
    if not attr:
        abort(400, description='Недопустимое поле для переключения')

    current_val = bool(getattr(server, attr))
    setattr(server, attr, not current_val)
    db.session.commit()

    return render_template(
        'servers/_row.html',
        server=server,
        passwords_visible=_passwords_visible(),
    )


# --- Domain management ---

@servers_bp.route('/<int:server_id>/domains', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def add_domain(server_id):
    """Add a domain to a server via HTMX."""
    server = _get_server_or_403(server_id)
    domain_value = (request.form.get('domain') or '').strip()
    if not domain_value:
        abort(400, description='Пустой домен')

    domain = Domain(domain=domain_value, server_id=server.id)
    db.session.add(domain)
    db.session.commit()
    return render_template('servers/_domain.html', domain=domain)


@servers_bp.route('/domains/<int:domain_id>/delete', methods=['POST'])
@login_required
@role_required('admin', 'superadmin')
def delete_domain(domain_id):
    """Delete a domain via HTMX."""
    domain = Domain.query.get_or_404(domain_id)
    # Здесь достаётся домен, а не сервер — проверять надо владельца.
    assert_can_access_server(domain.server)
    db.session.delete(domain)
    db.session.commit()
    return '', 204

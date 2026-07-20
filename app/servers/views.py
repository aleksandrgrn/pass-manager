"""Server CRUD + HTMX endpoints."""
from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    jsonify, current_app, abort
)
from flask_login import login_required, current_user
from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models import Server, Domain
from app.servers.forms import (
    ServerForm, ServerFilterForm,
    INLINE_EDITABLE_FIELDS, INLINE_TOGGLE_FIELDS,
)

servers_bp = Blueprint('servers', __name__)


# Sortable columns whitelist
SORTABLE_COLUMNS = {
    'id': Server.id,
    'name': Server.name,
    'ip_address': Server.ip_address,
    'provider': Server.provider,
    'active': Server.active,
    'has_exim': Server.has_exim,
    'has_squid': Server.has_squid,
    'has_vpn': Server.has_vpn,
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


@servers_bp.route('/')
@login_required
def list_servers():
    """Main table page."""
    form = ServerFilterForm(request.args)
    sort = request.args.get('sort', 'id')
    direction = request.args.get('dir', 'asc')

    query = Server.query
    query = _apply_filters(query, form)

    # Sorting with whitelist
    column = SORTABLE_COLUMNS.get(sort, Server.id)
    query = query.order_by(column.desc() if direction == 'desc' else column.asc())

    page = request.args.get('page', 1, type=int)
    per_page = current_app.config.get('ITEMS_PER_PAGE', 50)
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    servers = pagination.items

    return render_template(
        'servers/list.html',
        servers=servers,
        pagination=pagination,
        filter_form=form,
        sort=sort,
        direction=direction,
        passwords_visible=_passwords_visible(),
    )


@servers_bp.route('/<int:server_id>')
@login_required
def detail(server_id):
    """Server detail (HTML fragment for HTMX swap or full page)."""
    server = Server.query.get_or_404(server_id)
    domains = server.domains.all()
    return render_template(
        'servers/detail.html',
        server=server,
        domains=domains,
        passwords_visible=_passwords_visible(),
    )


@servers_bp.route('/new', methods=['GET', 'POST'])
@login_required
def create():
    """Add a new server. Available to all authenticated users."""
    form = ServerForm()
    if form.validate_on_submit():
        server = Server()
        form.populate_obj(server)
        db.session.add(server)
        db.session.commit()
        flash(f'Сервер «{server.name}» добавлен.', 'success')
        return redirect(url_for('servers.list_servers'))
    return render_template('servers/form.html', form=form, title='Новый сервер')


@servers_bp.route('/<int:server_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(server_id):
    """Edit a server (full form)."""
    server = Server.query.get_or_404(server_id)
    form = ServerForm(obj=server)
    if form.validate_on_submit():
        form.populate_obj(server)
        db.session.commit()
        flash(f'Сервер «{server.name}» обновлён.', 'success')
        return redirect(url_for('servers.list_servers'))
    return render_template('servers/form.html', form=form, title=f'Редактирование: {server.name}')


@servers_bp.route('/<int:server_id>/delete', methods=['POST'])
@login_required
def delete(server_id):
    """Delete a server."""
    server = Server.query.get_or_404(server_id)
    name = server.name
    db.session.delete(server)
    db.session.commit()
    flash(f'Сервер «{name}» удалён.', 'info')

    if request.headers.get('HX-Request'):
        return '', 204  # HTMX: remove row client-side
    return redirect(url_for('servers.list_servers'))


# --- HTMX inline editing endpoints ---

@servers_bp.route('/<int:server_id>/field', methods=['POST'])
@login_required
def edit_field(server_id):
    """Inline-edit a single text field via HTMX.

    Expected form fields: field=<name>, value=<new value>
    Returns the updated cell.
    """
    server = Server.query.get_or_404(server_id)
    field_name = (request.form.get('field') or '').strip()
    value = request.form.get('value', '').strip()

    attr = INLINE_EDITABLE_FIELDS.get(field_name)
    if not attr:
        abort(400, description='Недопустимое поле для редактирования')

    # Password fields restricted to users with permission
    if 'password' in field_name or 'pass' in field_name:
        if not _passwords_visible():
            abort(403, description='Недостаточно прав для редактирования пароля')

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
def toggle_field(server_id):
    """Toggle a boolean field (services, active) via HTMX."""
    server = Server.query.get_or_404(server_id)
    field_name = (request.form.get('field') or '').strip()

    attr = INLINE_TOGGLE_FIELDS.get(field_name)
    if not attr:
        abort(400, description='Недопустимое поле для переключения')

    current_val = bool(getattr(server, attr))
    setattr(server, attr, not current_val)
    db.session.commit()

    return render_template(
        'servers/_cell.html',
        server=server,
        field=field_name,
        value=getattr(server, attr),
        passwords_visible=_passwords_visible(),
    )


# --- Domain management ---

@servers_bp.route('/<int:server_id>/domains', methods=['POST'])
@login_required
def add_domain(server_id):
    """Add a domain to a server via HTMX."""
    server = Server.query.get_or_404(server_id)
    domain_value = (request.form.get('domain') or '').strip()
    if not domain_value:
        abort(400, description='Пустой домен')

    domain = Domain(domain=domain_value, server_id=server.id)
    db.session.add(domain)
    db.session.commit()
    return render_template('servers/_domain.html', domain=domain)


@servers_bp.route('/domains/<int:domain_id>/delete', methods=['POST'])
@login_required
def delete_domain(domain_id):
    """Delete a domain via HTMX."""
    domain = Domain.query.get_or_404(domain_id)
    db.session.delete(domain)
    db.session.commit()
    return '', 204

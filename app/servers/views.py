"""Server CRUD + HTMX endpoints."""
import io
import json
import os
import posixpath
import time
from contextlib import closing, contextmanager

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    current_app, abort, Response, send_file
)
from flask_login import login_required, current_user
from sqlalchemy import or_

from app.extensions import db
from app.models import (
    Server, Domain, ProvisioningJob, ServerGroup, ServerGroupMembership,
    AccessAssignment, FileAccessLog,
)
from app.access.rules import (
    assert_can_access_server, visible_servers, can_self_grant,
    files_denial, has_active_grant,
)
from app.auth.decorators import role_required
from app.services import netcheck, sftp, vps_client
from app.servers.forms import (
    ServerForm, ServerFilterForm,
    INLINE_EDITABLE_FIELDS, INLINE_TOGGLE_FIELDS,
    PASSWORD_FORM_FIELDS,
)
from app.services.provisioning import OnboardingLockedError, start_onboarding

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
        # % и _ из запроса — буквальные символы, а не шаблон LIKE
        escaped = q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        like = f'%{escaped}%'
        query = query.filter(or_(
            Server.name.ilike(like, escape='\\'),
            Server.ip_address.ilike(like, escape='\\'),
            Server.provider.ilike(like, escape='\\'),
            Server.notes.ilike(like, escape='\\'),
        ))
    # Неактуальные (в старой системе — тире в начале имени, таких 182 из 401)
    # прячем из обычного просмотра, но не из поиска: пустой экран в ответ на
    # запрос о существующем сервере читается как «его нет», а это худший из
    # возможных ответов — человек пойдёт заводить дубль.
    if not form.show_inactive.data and not q:
        query = query.filter(Server.active.is_(True))
    return query


def _passwords_visible():
    """Whether current user can see password columns."""
    return current_user.is_authenticated and current_user.can_view_passwords


def _access_cells(servers):
    """Что показать в колонке доступа: иконка сотруднику, счётчик суперадмину.

    Возвращает две карты по id сервера. Непустая всегда ровно одна: суперадмин
    себе доступ не выдаёт, поэтому иконка ему не нужна, а сотруднику незачем
    считать чужие выдачи.
    """
    if current_user.is_superadmin:
        counts = dict(
            db.session.query(AccessAssignment.server_id, db.func.count())
            .filter(AccessAssignment.state == 'active')
            .group_by(AccessAssignment.server_id)
            .all()
        )
        return {}, {server.id: counts.get(server.id, 0) for server in servers}

    granted = {
        row[0] for row in
        AccessAssignment.query
        .with_entities(AccessAssignment.server_id)
        .filter(
            AccessAssignment.user_id == current_user.id,
            AccessAssignment.state == 'active',
        )
        .all()
    }
    states = {}
    for server in servers:
        if server.id in granted:
            states[server.id] = 'has'
        elif not can_self_grant(current_user, server):
            # Сегодня недостижимо: правило видимости пускает не-суперадмина либо
            # к серверам своих групп, либо к тем, где у него активная выдача, —
            # а та уже разобрана веткой выше. Ветка стоит страховкой на случай,
            # если visible_servers когда-нибудь ослабят: тогда кнопка не появится
            # там, где grant_self ответит 403. Тестом не покрывается сознательно.
            states[server.id] = 'none'
        elif server.vps_manager_server_id:
            states[server.id] = 'can'
        else:
            states[server.id] = 'noconn'
    return states, {}


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
    access_states, access_counts = _access_cells(servers)

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
        access_states=access_states,
        access_counts=access_counts,
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
        can_grant=can_self_grant(current_user, server),
        has_access=AccessAssignment.query.filter_by(
            user_id=current_user.id, server_id=server.id, state='active',
        ).first() is not None,
    )


def _grant_access(user, server):
    """Пытается выдать пользователю личный доступ на сервер. Общая логика для
    точечной выдачи (`grant_self`) и массовой (C3-2, `app/access/views.py`).

    Возвращает (status, detail):
    - 'granted'       — доступ выдан только что, detail=None;
    - 'already'       — активная выдача уже была, detail=None;
    - 'not_connected' — сервер не подключён к VPS Manager, detail=None;
    - 'key_failed'    — не удалось создать личный ключ, detail=сообщение vps_client;
    - 'deploy_failed' — не удалось раскатать ключ на сервер, detail=сообщение vps_client.
    """
    if server.vps_manager_server_id is None:
        return 'not_connected', None

    existing = AccessAssignment.query.filter_by(
        user_id=user.id, server_id=server.id, state='active',
    ).first()
    if existing is not None:
        return 'already', None

    key_id = user.vps_manager_key_id
    if key_id is None:
        # Р: тип rsa, не ed25519 — в парке есть машины со старым SSH.
        resp = vps_client.generate_key(name=user.username, key_type='rsa')
        if not resp.get('success'):
            return 'key_failed', resp.get('message')
        key_id = resp['id']
        user.vps_manager_key_id = key_id
        db.session.commit()

    # server_id тут — номер машины на стороне VPS Manager, не наш server.id.
    resp = vps_client.deploy_key(key_id=key_id, server_id=server.vps_manager_server_id)
    if not resp.get('success'):
        return 'deploy_failed', resp.get('message')

    db.session.add(AccessAssignment(
        server_id=server.id,
        user_id=user.id,
        state='active',
        granted_by=user.id,
        vps_manager_key_id=key_id,
    ))
    db.session.commit()
    return 'granted', None


@servers_bp.route('/<int:server_id>/grant-self', methods=['POST'])
@login_required
def grant_self(server_id):
    """C2: выдать себе доступ на сервер своей группы личным ключом."""
    server = _get_server_or_403(server_id)

    if not can_self_grant(current_user, server):
        abort(403, description='Самостоятельная выдача доступна только на серверах ваших групп')

    htmx = request.headers.get('HX-Request')

    def _fail(message):
        """Отказ: причину человеку показывает карточка, поэтому уходим на неё.

        Под HTMX редирект нельзя отдавать телом ответа — заголовок HX-Redirect
        заставляет браузер перейти по-настоящему, и flash виден на карточке.
        """
        flash(message, 'error')
        if htmx:
            return '', 204, {'HX-Redirect': url_for('servers.detail', server_id=server.id)}
        return redirect(url_for('servers.detail', server_id=server.id))

    def _row():
        """Перерисованная строка списка — ответ на успешный клик по иконке."""
        access_states, access_counts = _access_cells([server])
        return render_template(
            'servers/_row.html',
            server=server,
            passwords_visible=_passwords_visible(),
            access_states=access_states,
            access_counts=access_counts,
        )

    status, detail = _grant_access(current_user, server)

    if status == 'not_connected':
        return _fail('Сервер не подключён к VPS Manager — обратитесь к суперадмину.')
    if status == 'key_failed':
        return _fail(f'Не удалось создать ключ: {detail}')
    if status == 'deploy_failed':
        return _fail(f'Не удалось раскатать ключ: {detail}')
    if status == 'already':
        if htmx:
            return _row()
        flash('Доступ на этот сервер у вас уже есть.', 'info')
        return redirect(url_for('servers.detail', server_id=server.id))

    # status == 'granted'
    if htmx:
        return _row()
    flash('Доступ выдан. Ключ можно скачать во вкладке «Доступ».', 'success')
    return redirect(url_for('servers.detail', server_id=server.id))


@servers_bp.app_template_global()
def netcheck_ip(value):
    """Для шаблона строки: та же проверка IP, что и в маршруте, — иначе кнопка
    активна у «—» или имени хоста в поле IP, а маршрут ответит 400."""
    return netcheck.parse_ip(value)


@servers_bp.route('/<int:server_id>/netcheck/<tool>', methods=['POST'])
@login_required
def netcheck_run(server_id, tool):
    """Ping или traceroute до сервера: NDJSON — строки вывода, в конце сводка."""
    server = _get_server_or_403(server_id)
    if tool not in netcheck.TOOLS:
        abort(404)
    ip = netcheck.parse_ip(server.ip_address)
    if ip is None:
        return 'У сервера нет корректного IP.', 400

    lock_dir = current_app.config.get('NETCHECK_LOCK_DIR') or os.path.join(
        current_app.instance_path, 'netcheck-locks')
    try:
        slots = netcheck.Slots(lock_dir, current_user.id)
    except netcheck.BusyError as e:
        return str(e), 429

    current_app.logger.info('netcheck user=%s server=%s ip=%s tool=%s',
                            current_user.username, server.id, ip, tool)
    argv = netcheck.build_command(tool, ip)
    timeout = netcheck.TIMEOUTS[tool]

    def _stream():
        lines = []
        # closing — чтобы при обрыве клиента процесс убил finally в run(),
        # а не сборщик мусора когда-нибудь потом.
        with closing(netcheck.run(argv, timeout)) as output:
            for line in output:
                lines.append(line)
                yield json.dumps({'line': line}, ensure_ascii=False) + '\n'
        summary = netcheck.summarize(tool, str(ip), lines)
        yield json.dumps({'summary': summary}, ensure_ascii=False) + '\n'

    response = Response(_stream(), mimetype='application/x-ndjson')
    # Слот снимается, когда ответ закрыт, — и после полного стрима, и после
    # обрыва клиента; сам генератор до своего finally может и не дойти.
    response.call_on_close(slots.release)
    # Без этого nginx копит ответ и отдаёт его целиком — построчность пропадёт.
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Cache-Control'] = 'no-cache'
    return response


# --- Окно файлов (SFTP) ---

# Шаблону строки — то же правило, что и маршрутам ниже.
servers_bp.add_app_template_global(files_denial)

def _files_log(server, action, path, result, size=None, detail=None):
    db.session.add(FileAccessLog(
        user_id=current_user.id, server_id=server.id, action=action,
        path=path, size=size, result=result, detail=detail,
    ))
    db.session.commit()


def _files_server(server_id, action, path):
    """Сервер, в файлы которого текущему пользователю можно; иначе 403 и запись."""
    server = Server.query.get_or_404(server_id)
    reason = files_denial(current_user, server, has_active_grant(current_user, server))
    if reason:
        _files_log(server, action, path, 'denied', detail=reason)
        abort(Response(reason, 403, mimetype='text/plain'))
    return server


def _files_error(server, action, path, exc):
    """Ошибка операции: строка в журнал, человеку — текст (его покажет окно)."""
    _files_log(server, action, path, 'error', detail=str(exc))
    return Response(str(exc), exc.status, mimetype='text/plain')


@contextmanager
def _files_session(server):
    """SFTP-сессия на сервер. Ключ берётся у VPS Manager на каждую операцию и
    живёт только в памяти: нет секрета в покое и нет устаревших копий."""
    started = time.monotonic()
    resp = vps_client.get_access_key(server.vps_manager_server_id)
    if not resp.get('success') or not resp.get('private_key'):
        raise sftp.SftpError(
            'VPS Manager не отдал ключ сервера: '
            + (resp.get('message') or 'причина не названа'))
    if not server.ip_address:
        raise sftp.SftpError('У сервера не указан IP.', 400)
    with sftp.connect(server.ip_address, server.ssh_port or 22,
                      server.ssh_username, resp['private_key'],
                      spent=time.monotonic() - started) as session:
        yield session


def _files_listing(server, listing, message=None):
    return render_template('servers/_files_list.html', server=server,
                           max_size=sftp.MAX_FILE_SIZE, message=message, **listing)


@servers_bp.route('/<int:server_id>/files')
@login_required
def files_list(server_id):
    """Каталог сервера — фрагмент для окна файлов. Без path — домашний каталог."""
    path = request.args.get('path') or ''
    server = _files_server(server_id, 'list', path)
    try:
        with _files_session(server) as session:
            listing = sftp.list_dir(session, path)
    except sftp.SftpError as e:
        return _files_error(server, 'list', path, e)
    _files_log(server, 'list', listing['path'], 'ok')
    return _files_listing(server, listing)


@servers_bp.route('/<int:server_id>/files/download')
@login_required
def files_download(server_id):
    """Файл с сервера — всегда вложением: он не должен открыться как страница
    приложения."""
    path = request.args.get('path') or ''
    server = _files_server(server_id, 'download', path)
    try:
        if not path:
            raise sftp.SftpError('Не указан файл.', 400)
        with _files_session(server) as session:
            data = sftp.read_file(session, path)
    except sftp.SftpError as e:
        return _files_error(server, 'download', path, e)
    _files_log(server, 'download', path, 'ok', size=len(data))
    # В Unix имя файла может содержать перевод строки и прочие управляющие
    # символы; в заголовок ответа им нельзя.
    name = ''.join(c for c in posixpath.basename(path) if c.isprintable())
    response = send_file(
        io.BytesIO(data), mimetype='application/octet-stream',
        as_attachment=True, download_name=name or 'file',
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
    return response


@servers_bp.route('/<int:server_id>/files/upload', methods=['POST'])
@login_required
def files_upload(server_id):
    """Файл с ПК — в каталог path. Поверх существующего — только с overwrite=1.
    Ответ — перерисованный каталог."""
    # Тело целиком ограничено MAX_CONTENT_LENGTH (app/config.py) — здесь
    # проверяется уже сам файл.
    directory = request.form.get('path') or ''
    upload = request.files.get('file')

    server = _files_server(server_id, 'upload', directory)
    name = ''
    target = None
    try:
        if upload is None or not directory:
            raise sftp.SftpError('Не выбран файл или каталог.', 400)
        # Браузер присылает имя без пути; путь в имени отбрасывается, а не
        # исполняется — файл ложится только в открытый каталог.
        name = posixpath.basename((upload.filename or '').replace('\\', '/'))
        data = upload.read(sftp.MAX_FILE_SIZE + 1)
        sftp.validate_upload(name, len(data))
        with _files_session(server) as session:
            target = sftp.write_file(
                session, directory, name, data,
                overwrite=request.form.get('overwrite') == '1')
            _files_log(server, 'upload', target, 'ok', size=len(data))
            listing = sftp.list_dir(session, directory)
    except sftp.SftpError as e:
        if target is not None:
            # Файл уже на месте и записан в журнал — не удалось только
            # перечитать каталог.
            _files_log(server, 'list', directory, 'error', detail=str(e))
            return Response(f'Файл загружен, но каталог перечитать не удалось: {e}',
                            502, mimetype='text/plain')
        return _files_error(server, 'upload', posixpath.join(directory, name), e)
    return _files_listing(server, listing, message=f'Файл «{name}» загружен.')


@servers_bp.route('/new', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'superadmin')
def create():
    """Add a new server. Available to all authenticated users."""
    form = ServerForm()
    form.require_password = True
    form.group_id.choices = _group_choices()
    if not form.group_id.choices:
        # Р6: возможность заводить серверы — свойство группы. Ни одной подходящей
        # группы нет → и заводить некуда, форму показывать бессмысленно.
        abort(403, description='Ни одна из ваших групп не может заводить серверы')

    if form.validate_on_submit():
        # Track C A3 (Р4): на заведении «Пароль root» — это текущий пароль от
        # хостера, то есть вход онбординга, а не значение поля. В модель он не
        # едет: pipeline держит его зашифрованным в steps_json и стирает после
        # успешного bootstrap, а servers.password заполнит шаг promote
        # сгенерированным значением.
        bootstrap_password = form.password.data
        del form['password']

        server = Server()
        form.populate_obj(server)
        if server.group_id == NO_GROUP_CHOICE:
            server.group_id = None  # SelectField отдаёт 0, в БД это NULL
        db.session.add(server)
        db.session.commit()
        flash(f'Сервер «{server.name}» добавлен.', 'success')

        try:
            job = start_onboarding(server, current_user, bootstrap_password)
        except OnboardingLockedError as exc:
            # FIX-6c: не должно случаться при создании нового сервера (job
            # ещё ни одного), но start_onboarding — общая точка входа.
            flash(str(exc), 'error')
            return redirect(url_for('servers.detail', server_id=server.id))
        return redirect(url_for('provisioning.job_page', job_id=job.id))
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

    # Форма заполнена из объекта, то есть несёт расшифрованные пароли. Кому их
    # не показывают — у того полей нет вовсе: спрятать в шаблоне мало (значение
    # всё равно уехало бы в HTML), а оставить в форме нельзя (populate_obj
    # затёр бы секрет пустым значением из POST).
    if not _passwords_visible():
        for field_name in PASSWORD_FORM_FIELDS:
            del form[field_name]

    if form.validate_on_submit():
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

def _is_password_field(field_name):
    """Секретное ли поле — по тому же списку, что режет форму редактирования.

    Раньше сверялось по подстроке 'pass' и закрывало от админа provider_password,
    web_pass, mgt_pass. Это лишнее: доступ к машине — только пароль root.
    """
    return field_name in PASSWORD_FORM_FIELDS


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

    access_states, access_counts = _access_cells([server])
    return render_template(
        'servers/_row.html',
        server=server,
        passwords_visible=_passwords_visible(),
        access_states=access_states,
        access_counts=access_counts,
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

"""История изменений сервера (GRSA-191).

Пишется одним перехватчиком `before_flush`, а не в каждом обработчике: сервер
меняют форма, inline-правка, переключатели, домены, конвейер подключения и
скрипты — забыть вызов в любом из них значило бы тихую дыру в истории.

Изменения одного flush по одному серверу — одна запись (`ServerChange`) с
элементами по полям (`ServerChangeItem`). История пишется в той же транзакции,
что и изменение: сбой здесь срывает сохранение, а не оставляет его без следа.
"""
import re
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import timedelta, timezone

from flask import has_request_context
from flask_login import current_user
from markupsafe import Markup, escape
from sqlalchemy import event, inspect, select
from sqlalchemy.orm import Session

from app.models import Domain, Server, ServerChange, ServerChangeItem, ServerGroup
from app.security import decrypt

# Поля, которые видит человек. Служебные (provisioning_status,
# bootstrap_request_id, password_pending, *_at) в историю не идут.
TRACKED_FIELDS = (
    'name', 'ip_address', 'ssh_port', 'ssh_username', 'provider', 'provider_login',
    'notes', 'active', 'os', 'cpu', 'ram', 'has_exim', 'has_squid', 'has_vpn',
    'website', 'web_login', 'vps_management_url', 'mgt_login', 'group_id',
    'vps_manager_server_id',
)
# Секреты — по колонке с токеном; в историю идёт только факт изменения.
SECRET_FIELDS = (
    'password_encrypted', 'provider_password_encrypted',
    'web_pass_encrypted', 'mgt_pass_encrypted',
)

SOURCE_MANUAL = 'manual'
SOURCE_SCRIPT = 'script'

CREATED = 'created'
DOMAIN_ADDED = 'domain_added'
DOMAIN_REMOVED = 'domain_removed'


SOURCE_ONBOARDING = 'onboarding'
SOURCE_NEW_MACHINE = 'new_machine'

# Автор и источник, заданные явно. Нужно конвейеру: его шаги исполняются в
# запросах опроса страницы job, и current_user там — тот, кто смотрит
# страницу, а не тот, кто запустил.
_context = ContextVar('server_change_context', default=None)


@contextmanager
def change_context(source, user_id, job_id=None):
    token = _context.set((user_id, source, job_id))
    try:
        yield
    finally:
        _context.reset(token)


def _author_source_job():
    explicit = _context.get()
    if explicit is not None:
        return explicit
    if has_request_context() and current_user.is_authenticated:
        return current_user.id, SOURCE_MANUAL, None
    return None, SOURCE_SCRIPT, None


FIELD_LABELS = {
    'name': 'Название', 'ip_address': 'IP', 'ssh_port': 'Порт SSH',
    'ssh_username': 'Пользователь SSH', 'provider': 'Провайдер',
    'provider_login': 'Логин провайдера', 'notes': 'Комментарии', 'active': 'Активен',
    'os': 'ОС', 'cpu': 'CPU', 'ram': 'RAM', 'has_exim': 'Exim', 'has_squid': 'Squid',
    'has_vpn': 'VPN', 'website': 'Website', 'web_login': 'Web login',
    'vps_management_url': 'URL панели', 'mgt_login': 'Логин панели', 'group_id': 'Группа',
    'vps_manager_server_id': 'VPS Manager',
    'password_encrypted': 'Пароль root', 'provider_password_encrypted': 'Пароль провайдера',
    'web_pass_encrypted': 'Web pass', 'mgt_pass_encrypted': 'Пароль панели',
    CREATED: 'Сервер заведён', DOMAIN_ADDED: 'Домен добавлен', DOMAIN_REMOVED: 'Домен удалён',
}
MONO_FIELDS = {'ip_address', 'ssh_port', DOMAIN_ADDED, DOMAIN_REMOVED}
SOURCE_LABELS = {
    SOURCE_MANUAL: 'правка вручную', SOURCE_SCRIPT: 'скрипт',
    SOURCE_ONBOARDING: 'подключение', SOURCE_NEW_MACHINE: 'новая машина у хостера',
}
# Фиксированное смещение, а не ZoneInfo: перехода на летнее время в Москве нет
# с 2014 года, а база часовых поясов на хосте не обязана быть.
_MSK = timezone(timedelta(hours=3))


def local_time(value):
    """created_at в SQLite — UTC без зоны (server_default now()); людям — по Москве."""
    if value is None:
        return ''
    return value.replace(tzinfo=timezone.utc).astimezone(_MSK).strftime('%d.%m.%Y %H:%M')


def highlight(value, q):
    """Текст с подсвеченными вхождениями запроса — для совпадений в ячейках списка.

    Экранирует сам: и значение, и запрос приходят от людей. inline-правка и
    копирование берут textContent, так что <mark> им не мешает."""
    text = '' if value is None else str(value)
    if not q or not text:
        return escape(text)
    parts, pos = [], 0
    for m in re.finditer(re.escape(q), text, re.IGNORECASE):
        parts += [escape(text[pos:m.start()]),
                  Markup('<mark class="hl">') + escape(m.group()) + Markup('</mark>')]
        pos = m.end()
    parts.append(escape(text[pos:]))
    return Markup('').join(parts)


def init_app(app):
    app.jinja_env.filters['history_time'] = local_time
    app.jinja_env.filters['highlight'] = highlight
    app.jinja_env.globals.update(
        HISTORY_FIELD_LABELS=FIELD_LABELS, HISTORY_SOURCE_LABELS=SOURCE_LABELS,
        HISTORY_MONO_FIELDS=MONO_FIELDS,
    )


def _normalize(value):
    # inline-правка пишет `value or None`, форма — пустую строку: для человека
    # это одно и то же «пусто», разницы в истории быть не должно. Браузер шлёт
    # textarea с \r\n, а импорт хранит \n — тоже не изменение.
    if isinstance(value, str):
        value = value.replace('\r\n', '\n')
    return None if value == '' else value


def _display(session, field, value):
    """Значение поля в том виде, в каком его поймёт человек."""
    if value is None:
        return None
    if field in ('has_exim', 'has_squid', 'has_vpn'):
        return 'вкл' if value else 'выкл'
    if field == 'active':
        return 'да' if value else 'нет'
    if field == 'group_id':
        group = session.get(ServerGroup, value)
        return group.name if group else f'#{value}'
    if field == 'vps_manager_server_id':
        return f'подключён (№ {value})'
    return str(value)


def _server_items(session, server):
    """Элементы истории для изменённого (persistent) сервера."""
    state = inspect(server)
    modified = [
        f for f in TRACKED_FIELDS + SECRET_FIELDS
        if state.attrs[f].history.added
    ]
    new_values = {}
    new_group = None
    # `server.group = …` меняет связь, а group_id ORM синхронизирует только
    # внутри flush — по колонке такое присваивание не видно.
    group_hist = state.attrs['group'].history
    if group_hist.has_changes():
        new_group = group_hist.added[0] if group_hist.added else None
        # У ещё не сохранённой группы id нет — имя берём из объекта ниже.
        new_values['group_id'] = new_group.id if new_group is not None else None
        if 'group_id' not in modified:
            modified.append('group_id')
    if not modified:
        return []

    # Прежние значения — из базы, а не из истории атрибута: после commit
    # атрибуты выгружены, и присваивание поверх выгруженного прежнего значения
    # не помнит (было бы «— → новый IP»). До flush в базе ещё старое.
    table = Server.__table__
    row = session.connection().execute(
        select(*(table.c[f] for f in modified)).where(table.c.id == server.id)
    ).one()

    items = []
    for field, old in zip(modified, row):
        new = new_values[field] if field in new_values else getattr(server, field)
        if field in SECRET_FIELDS:
            # Fernet даёт новый токен на каждое шифрование, а форма суперадмина
            # перезаписывает пароли при каждом сохранении — сравниваем смысл.
            # Без _normalize: в пароле \r\n и \n — разные символы.
            if (decrypt(old) or None) != (decrypt(new) or None):
                items.append(ServerChangeItem(field=field, is_secret=True))
            continue
        old, new = _normalize(old), _normalize(new)
        if field == 'ssh_port':
            # У старых записей порта нет, и везде он читается как `ssh_port or 22`.
            old, new = old or 22, new or 22
        if old == new:
            continue
        if field == 'vps_manager_server_id' and old is None:
            old_display = 'не подключён'
        else:
            old_display = _display(session, field, old)
        if field == 'group_id' and new_group is not None:
            new_display = new_group.name
        elif field == 'vps_manager_server_id' and new is None:
            new_display = 'не подключён'
        else:
            new_display = _display(session, field, new)
        items.append(ServerChangeItem(field=field, old_value=old_display, new_value=new_display))
    return items


def _domain_items(session, domain, deleted_servers):
    """Домен, изменённый не через session.add/delete: переименован, перенесён
    или отвязан от сервера (`server.domains.remove(d)` — delete-orphan удалит его
    уже внутри flush). Для истории это «удалён» у прежнего и «добавлен» у нового."""
    state = inspect(domain)
    server_hist = state.attrs['server'].history
    if not (server_hist.has_changes() or state.attrs['domain'].history.added
            or state.attrs['server_id'].history.added):
        return {}
    table = Domain.__table__
    old_server_id, old_name = session.connection().execute(
        select(table.c.server_id, table.c.domain).where(table.c.id == domain.id)
    ).one()
    if server_hist.has_changes():
        new_server = next((s for s in server_hist.added if s is not None), None)
    else:
        new_server = session.get(Server, domain.server_id) if domain.server_id else None
    old_server = session.get(Server, old_server_id)
    if new_server is old_server and domain.domain == old_name:
        return {}
    out = {}
    if old_server is not None and old_server not in deleted_servers:
        out.setdefault(old_server, []).append(
            ServerChangeItem(field=DOMAIN_REMOVED, old_value=old_name))
    if new_server is not None:
        out.setdefault(new_server, []).append(
            ServerChangeItem(field=DOMAIN_ADDED, new_value=domain.domain))
    return out


# Запись истории, открытая в текущей транзакции, по серверу: autoflush посреди
# сохранения (любой запрос) дробит его на несколько flush, а для человека это
# одно сохранение. Сбрасывается на commit/rollback.
_OPEN_CHANGES = 'grsa191_open_changes'


# ponytail: after_rollback срабатывает и на откат savepoint (begin_nested), и тогда
# правки внешней транзакции после него лягут во вторую запись. Сейчас savepoint в
# проекте нет; появятся — чистить только при откате корневой транзакции.
@event.listens_for(Session, 'after_commit')
@event.listens_for(Session, 'after_rollback')
def _close_open_changes(session):
    session.info.pop(_OPEN_CHANGES, None)


@event.listens_for(Session, 'before_flush')
def _record_server_changes(session, flush_context, instances):
    deleted_servers = {o for o in session.deleted if isinstance(o, Server)}
    pending = {}  # server -> [items]

    for obj in session.new:
        if isinstance(obj, Server):
            pending.setdefault(obj, []).append(ServerChangeItem(field=CREATED))
        elif isinstance(obj, Domain):
            server = obj.server or (obj.server_id and session.get(Server, obj.server_id))
            if server is not None:
                pending.setdefault(server, []).append(
                    ServerChangeItem(field=DOMAIN_ADDED, new_value=obj.domain))

    for obj in session.deleted:
        if isinstance(obj, ServerGroup):
            # group_id серверов удалённой группы ORM обнулит уже внутри flush —
            # в dirty их сейчас нет, и без этой ветки следа в истории не было бы.
            for server in obj.servers:
                if server not in deleted_servers:
                    pending.setdefault(server, []).append(
                        ServerChangeItem(field='group_id', old_value=obj.name))
        elif isinstance(obj, Domain):
            # `d.server = None` перед удалением обнуляет связь, но не колонку.
            server = obj.server or (obj.server_id and session.get(Server, obj.server_id))
            # Домены, уходящие каскадом вместе с сервером, не пишем: истории
            # удалённого сервера больше нет.
            if server is not None and server not in deleted_servers:
                pending.setdefault(server, []).append(
                    ServerChangeItem(field=DOMAIN_REMOVED, old_value=obj.domain))

    for obj in session.dirty:
        if isinstance(obj, Server) and obj not in deleted_servers \
                and session.is_modified(obj, include_collections=False):
            items = _server_items(session, obj)
            if items:
                pending.setdefault(obj, []).extend(items)
        elif isinstance(obj, Domain) and session.is_modified(obj, include_collections=False):
            for server, items in _domain_items(session, obj, deleted_servers).items():
                pending.setdefault(server, []).extend(items)

    if not pending:
        return
    user_id, source, job_id = _author_source_job()
    open_changes = session.info.setdefault(_OPEN_CHANGES, {})
    for server, items in pending.items():
        existing = open_changes.get(server)
        if existing is None and job_id is not None and server.id is not None:
            # Шаги одного запуска конвейера коммитятся по отдельности, но для
            # человека это одно событие («новая машина»): дописываем в ту же запись.
            existing = session.execute(
                select(ServerChange).where(ServerChange.server_id == server.id,
                                           ServerChange.job_id == job_id)
            ).scalars().first()
        if existing is not None:
            for item in items:
                item.change = existing
                session.add(item)
        else:
            existing = ServerChange(server=server, user_id=user_id, source=source,
                                    job_id=job_id, items=items)
            session.add(existing)
        open_changes[server] = existing

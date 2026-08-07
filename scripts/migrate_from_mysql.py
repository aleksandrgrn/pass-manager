"""Migrate data from the legacy MySQL database into SQLite.

Supports two input modes:
    1. Direct connection to a live MySQL server (preferred, requires PyMySQL).
       Configure via env vars: MYSQL_HOST, MYSQL_PORT, MYSQL_USER,
       MYSQL_PASSWORD, MYSQL_DB.
    2. Parse a .sql dump (mysqldump output). Slower but works offline.

Expected legacy tables (schema taken from the live dump, SHOW CREATE TABLE):

    vps            (id, VPS, Login, Password, IP, Provider, PLogin, PPassword,
                    exim, squid, vpn, Notes)                        -- 12 columns
    vps_details    (vps_id, active, os, cpu, ram, drive)            -- 6 columns
    vps_management (vps_id, website, web_login, web_pass,
                    vps_management, mgt_login, mgt_pass)             -- 7 columns
    domains        (domain_id, domain, vpsid)                       -- 3 columns; vpsid is varchar

`exim`/`squid`/`vpn` are varchar, not numbers — `_bool()` already handles strings.

Usage:
    # Live MySQL
    MYSQL_HOST=... MYSQL_USER=... MYSQL_PASSWORD=... MYSQL_DB=vps \\
        python scripts/migrate_from_mysql.py

    # .sql dump
    python scripts/migrate_from_mysql.py --dump /path/to/vps_backup.sql

    # Common flags
    --dry-run            : only print, do not write
    --reset              : drop and recreate target tables first
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models import User, Server, Domain, ServerGroup


# ---------------------------------------------------------------------------
# Parsing a .sql dump
# ---------------------------------------------------------------------------

# Matches only the INSERT header: `INSERT INTO <table> [(cols)] VALUES`.
# The statement body is scanned separately by `_find_statement_end`, because
# a `;` inside a string value (password, note) must not end the statement.
INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+`?(?P<table>\w+)`?\s*(?:\([^)]+\)\s*)?VALUES\s*",
    re.IGNORECASE,
)


def _find_statement_end(sql, start):
    """Find the `;` that terminates the INSERT statement starting at `start`.

    Walks the SQL char-by-char tracking quote state (a backslash escapes the
    next char, so ``\\'`` inside a value does not close the string) and
    parenthesis depth. Returns the index of the first `;` that sits outside
    quotes and outside parentheses, or ``len(sql)`` if none is found.

    Quote tracking matters because `(`/`)` inside string values must not
    affect the depth. A `;` inside a value is always at depth >= 1 (values
    live inside tuple parentheses), so the depth-0 check already excludes it.
    """
    depth = 0
    in_string = False
    escape = False
    i = start
    n = len(sql)
    while i < n:
        ch = sql[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == '\\':
            escape = True
            i += 1
            continue
        if ch == "'":
            in_string = not in_string
            i += 1
            continue
        if not in_string:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth = max(0, depth - 1)
        if ch == ';' and depth == 0:
            return i
        i += 1
    return n


def _split_tuples(values_blob):
    """Split '(...),(...),(...)' into list of strings inside parentheses."""
    rows = []
    depth = 0
    current = []
    in_string = False
    escape = False
    for ch in values_blob:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == '\\':
            current.append(ch)
            escape = True
            continue
        if ch == "'":
            in_string = not in_string
            current.append(ch)
            continue
        if not in_string:
            if ch == '(':
                if depth == 0:
                    current = []
                else:
                    current.append(ch)
                depth += 1
                continue
            if ch == ')':
                depth -= 1
                if depth == 0:
                    rows.append(''.join(current))
                else:
                    current.append(ch)
                continue
            if depth == 0:
                # whitespace/comma between tuples
                continue
        current.append(ch)
    return rows


def _parse_sql_value(token):
    """Parse a single SQL scalar into a Python value."""
    token = token.strip()
    if token.upper() in ('NULL',):
        return None
    if (token.startswith("'") and token.endswith("'")) or \
       (token.startswith('"') and token.endswith('"')):
        # Unescape
        inner = token[1:-1]
        inner = inner.replace("\\'", "'").replace('\\"', '"').replace('\\\\', '\\').replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t')
        return inner
    # Numeric
    try:
        if '.' in token:
            return float(token)
        return int(token)
    except ValueError:
        return token


def _parse_tuple(tuple_str):
    """Parse a single (a, b, 'c') tuple into a list of values."""
    out = []
    depth = 0
    in_string = False
    escape = False
    current = []
    for ch in tuple_str:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == '\\':
            current.append(ch)
            escape = True
            continue
        if ch == "'":
            in_string = not in_string
            current.append(ch)
            continue
        if not in_string and ch == ',' and depth == 0:
            out.append(_parse_sql_value(''.join(current)))
            current = []
            continue
        current.append(ch)
    if current:
        out.append(_parse_sql_value(''.join(current)))
    return out


def parse_sql_dump(path):
    """Parse a mysqldump file and return dict {table: [rows]}.

    Each row is a list of values (in column order as in the dump).
    """
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        sql = fh.read()

    tables = {}
    for m in INSERT_RE.finditer(sql):
        table = m.group('table').lower()
        stmt_end = _find_statement_end(sql, m.end())
        rows_blob = sql[m.end():stmt_end]
        rows = []
        for tuple_str in _split_tuples(rows_blob):
            rows.append(_parse_tuple(tuple_str))
        tables.setdefault(table, []).extend(rows)
    return tables


# ---------------------------------------------------------------------------
# Mapping legacy rows → new models
# ---------------------------------------------------------------------------

def _bool(val, default=False):
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return int(val) != 0
    if isinstance(val, str):
        return val.strip() in ('1', 'true', 'TRUE', 'True', 'y', 'Y', 'yes', 'YES')
    return default


def import_legacy_data(tables, *, dry_run=False, reset=False, group=None):
    vps_rows = tables.get('vps', [])
    details_rows = tables.get('vps_details', [])
    management_rows = tables.get('vps_management', [])
    domains_rows = tables.get('domains', [])

    # Index details/management by vps_id (first column)
    details_by_vps = {}
    for row in details_rows:
        if not row:
            continue
        details_by_vps[row[0]] = row

    mgmt_by_vps = {}
    for row in management_rows:
        if not row:
            continue
        mgmt_by_vps[row[0]] = row

    if reset:
        if dry_run:
            print('[dry-run] Would delete existing Server/Domain rows')
        else:
            Domain.query.delete()
            Server.query.delete()
            db.session.commit()
            print('✓ Cleared Server and Domain tables')

    # Разрешаем имя группы в идентификатор до цикла по vps_rows.
    group_id = None
    if group:
        existing = ServerGroup.query.filter_by(name=group).first()
        if existing:
            group_id = existing.id
        elif dry_run:
            print(f'[dry-run] Would create group «{group}»')
        else:
            new_group = ServerGroup(name=group)
            db.session.add(new_group)
            db.session.commit()
            group_id = new_group.id

    created_servers = 0
    created_domains = 0
    skipped = 0
    skipped_wrong_cols = 0
    skipped_empty_name = 0
    inactive_by_dash = 0
    notes_with_disk = 0
    # Набор id серверов, которые реально созданы (после всех пропусков).
    # Домен, чей vpsid не входит в этот набор, — сирота, его не переносим.
    created_server_ids = set()
    domains_skipped_len = 0
    domains_skipped_vpsid = 0
    domains_skipped_empty_name = 0
    domains_skipped_orphan = 0

    for row in vps_rows:
        if len(row) != 12:
            print(f'⚠️  vps row has {len(row)} columns instead of 12, skipping')
            skipped += 1
            skipped_wrong_cols += 1
            continue

        # Real schema (SHOW CREATE TABLE): id, VPS, Login, Password, IP,
        # Provider, PLogin, PPassword, exim, squid, vpn, Notes
        server_id = row[0]
        name_raw = row[1]
        login = row[2]
        password = row[3]
        ip = row[4]
        provider = row[5]
        plogin = row[6]
        ppassword = row[7]
        has_exim = _bool(row[8])
        has_squid = _bool(row[9])
        has_vpn = _bool(row[10])
        notes = row[11]

        # ssh_username NOT NULL, default 'root': пустой Login → 'root'.
        ssh_username = (str(login).strip() if login is not None else '') or 'root'

        # Флага актуальности в старой базе не было: тире в начале имени
        # означает, что сервер неактуален. vps_details.active не используем —
        # владелец базы этой колонкой не пользовался.
        name = str(name_raw).strip() if name_raw is not None else ''
        if name.startswith('-'):
            active = False
            name = name.lstrip('- ').strip()
            inactive_by_dash += 1
        else:
            active = True
        if not name:
            print('⚠️  vps row has empty name, skipping')
            skipped += 1
            skipped_empty_name += 1
            continue

        # vps_details: vps_id, active, os, cpu, ram, drive
        details = details_by_vps.get(server_id)
        os_val = details[2] if details and len(details) > 2 else None
        cpu = details[3] if details and len(details) > 3 else None
        ram = details[4] if details and len(details) > 4 else None
        drive = details[5] if details and len(details) > 5 else None

        # vps_management: vps_id, website, web_login, web_pass,
        #                 vps_management, mgt_login, mgt_pass
        mgmt = mgmt_by_vps.get(server_id)
        website = mgmt[1] if mgmt and len(mgmt) > 1 else None
        web_login = mgmt[2] if mgmt and len(mgmt) > 2 else None
        web_pass = mgmt[3] if mgmt and len(mgmt) > 3 else None
        vps_mgmt_url = mgmt[4] if mgmt and len(mgmt) > 4 else None
        mgt_login = mgmt[5] if mgmt and len(mgmt) > 5 else None
        mgt_pass = mgmt[6] if mgmt and len(mgmt) > 6 else None

        # `drive` поля в модели не имеет — дописываем в notes.
        if drive is not None and str(drive).strip():
            notes = f'{notes}\nДиск: {drive}' if notes else f'Диск: {drive}'
            notes_with_disk += 1

        server = Server(
            id=server_id,
            name=name,
            ssh_username=ssh_username,
            password=password,
            ip_address=ip,
            provider=provider,
            provider_login=plogin,
            provider_password=ppassword,
            notes=notes,
            active=active,
            os=os_val,
            cpu=cpu,
            ram=ram,
            has_exim=has_exim,
            has_squid=has_squid,
            has_vpn=has_vpn,
            website=website,
            web_login=web_login,
            web_pass=web_pass,
            vps_management_url=vps_mgmt_url,
            mgt_login=mgt_login,
            mgt_pass=mgt_pass,
            group_id=group_id,
        )

        if dry_run:
            print(f'[dry-run] Would import server #{server_id} «{name}»')
        else:
            db.session.merge(server)
        created_servers += 1
        created_server_ids.add(server_id)

    # Domains — legacy table column order: (domain_id, domain, vpsid).
    # vpsid это varchar: приводим к числу явно. Эвристики «угадай порядок
    # колонок по типам значений» больше нет — она превращала несовпадение
    # схемы в тихий мусор.
    for row in domains_rows:
        if len(row) < 3:
            domains_skipped_len += 1
            continue
        domain_name = row[1]
        vpsid_raw = row[2]
        try:
            vpsid = int(str(vpsid_raw).strip())
        except (TypeError, ValueError):
            vpsid = None
        if not vpsid:
            domains_skipped_vpsid += 1
            continue
        if not isinstance(domain_name, str) or not domain_name.strip():
            domains_skipped_empty_name += 1
            continue
        # Домен указывает на сервер, которого в новой базе не будет:
        # либо строки vps с таким id нет в дампе, либо сервер был пропущен
        # (пустое имя и т.п.). Такой домен не переносим — считаем и не вешаем
        # ссылку в никуда.
        if vpsid not in created_server_ids:
            domains_skipped_orphan += 1
            continue
        if dry_run:
            print(f'[dry-run] Would import domain {domain_name} → server {vpsid}')
        else:
            db.session.add(Domain(domain=domain_name, server_id=vpsid))
        created_domains += 1

    domains_bound = created_domains
    domains_accounted = (
        domains_bound
        + domains_skipped_len
        + domains_skipped_vpsid
        + domains_skipped_empty_name
        + domains_skipped_orphan
    )
    vps_accounted = created_servers + skipped

    print(f'\n✓ Imported: {created_servers} servers, {created_domains} domains, skipped {skipped}')
    print(f'  vps: parsed {len(vps_rows)}, created {created_servers}, '
          f'skipped {skipped} (wrong columns: {skipped_wrong_cols}, empty name: {skipped_empty_name})')
    print(f'  inactive by dash: {inactive_by_dash}')
    print(f'  domains: parsed {len(domains_rows)}, bound {created_domains}, '
          f'skipped by vpsid: {domains_skipped_vpsid}, '
          f'empty name: {domains_skipped_empty_name}, '
          f'orphan (no created server): {domains_skipped_orphan}, '
          f'wrong column count: {domains_skipped_len}')
    print(f'  notes with disk: {notes_with_disk}')

    if domains_accounted != len(domains_rows) or vps_accounted != len(vps_rows):
        # Любая строка, что исчезла, не увеличив ни один счётчик, — дефект:
        # именно он стоил нам ручной разовой проверки против боевого дампа.
        raise RuntimeError(
            'Migration report does not reconcile: '
            f'domains accounted {domains_accounted} != {len(domains_rows)} '
            f'parsed; vps accounted {vps_accounted} != {len(vps_rows)} parsed'
        )

    # Сходимость отчёта проверена и напечатана; только теперь можно писать.
    if not dry_run:
        db.session.commit()

    return created_servers, created_domains, skipped


# ---------------------------------------------------------------------------
# Live MySQL mode (optional)
# ---------------------------------------------------------------------------

def read_from_live_mysql():
    try:
        import pymysql
    except ImportError:
        print('✗ pymysql not installed. Run: pip install pymysql', file=sys.stderr)
        sys.exit(2)

    host = os.environ.get('MYSQL_HOST', '127.0.0.1')
    port = int(os.environ.get('MYSQL_PORT', '3306'))
    user = os.environ.get('MYSQL_USER', 'root')
    password = os.environ.get('MYSQL_PASSWORD', '')
    db_name = os.environ.get('MYSQL_DB', 'vps')

    conn = pymysql.connect(host=host, port=port, user=user, password=password, database=db_name)
    tables = {}
    try:
        with conn.cursor() as cur:
            for table in ('vps', 'vps_details', 'vps_management', 'domains'):
                cur.execute(f'SELECT * FROM {table}')
                tables[table] = [list(row) for row in cur.fetchall()]
    finally:
        conn.close()
    return tables


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Migrate legacy MySQL data into SQLite')
    parser.add_argument('--dump', help='Path to .sql dump file (mysqldump output)')
    parser.add_argument('--live', action='store_true', help='Read from live MySQL via env vars')
    parser.add_argument('--dry-run', action='store_true', help='Print actions only')
    parser.add_argument('--reset', action='store_true', help='Drop existing servers/domains first')
    parser.add_argument('--group', help='Положить переносимые серверы в группу с этим именем (создаётся, если её нет)')
    args = parser.parse_args()

    if not args.dump and not args.live:
        parser.error('Either --dump <path> or --live is required')

    if args.dump:
        print(f'Parsing SQL dump: {args.dump}')
        tables = parse_sql_dump(args.dump)
    else:
        print('Reading from live MySQL...')
        tables = read_from_live_mysql()

    summary = ', '.join(f'{k}={len(v)}' for k, v in tables.items())
    print(f'Found rows: {summary}')

    config_name = os.environ.get('FLASK_CONFIG', 'development')
    app = create_app(config_name)
    with app.app_context():
        import_legacy_data(tables, dry_run=args.dry_run, reset=args.reset, group=args.group)


if __name__ == '__main__':
    main()

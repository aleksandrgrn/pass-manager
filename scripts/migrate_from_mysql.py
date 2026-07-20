"""Migrate data from the legacy MySQL database into SQLite.

Supports two input modes:
    1. Direct connection to a live MySQL server (preferred, requires PyMySQL).
       Configure via env vars: MYSQL_HOST, MYSQL_PORT, MYSQL_USER,
       MYSQL_PASSWORD, MYSQL_DB.
    2. Parse a .sql dump (mysqldump output). Slower but works offline.

Expected legacy tables (from readme/vps2/):
    vps            (id, VPS, Password, IP, Provider, PLogin, PPassword, exim, squid, vpn, Notes, active)
    vps_details    (vps_id, website, web_login, web_pass, vps_management, mgt_login, mgt_pass)
    vps_management (vps_id)
    domains        (domain_id, domain, vpsid)

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
from app.models import User, Server, Domain


# ---------------------------------------------------------------------------
# Parsing a .sql dump
# ---------------------------------------------------------------------------

# Matches: INSERT INTO `vps` VALUES (1,'name','pass',...);
INSERT_RE = re.compile(
    r"INSERT\s+INTO\s+`?(?P<table>\w+)`?\s*(?:\([^)]+\)\s*)?VALUES\s*(?P<rows>.*?);",
    re.IGNORECASE | re.DOTALL,
)


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
        rows_blob = m.group('rows')
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


def import_legacy_data(tables, *, dry_run=False, reset=False):
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

    created_servers = 0
    created_domains = 0
    skipped = 0

    for row in vps_rows:
        if len(row) < 9:
            print(f'⚠️  vps row too short, skipping: {row}')
            skipped += 1
            continue
        # Legacy column order from readme/vps2/ajax_table.class.php:
        # active, os, cpu, ram, id, VPS, Password, IP, Provider,
        # PLogin, PPassword, exim, squid, vpn, Notes
        # We support both orders by trying to match: id first vs active first.
        if isinstance(row[0], int) and (len(row) >= 14):
            # Order: id, VPS, Password, IP, Provider, PLogin, PPassword, exim, squid, vpn, Notes, active, os, cpu, ram
            server_id = row[0]
            name = row[1]
            password = row[2]
            ip = row[3]
            provider = row[4]
            plogin = row[5]
            ppassword = row[6]
            has_exim = _bool(row[7])
            has_squid = _bool(row[8])
            has_vpn = _bool(row[9])
            notes = row[10] if len(row) > 10 else None
            active = _bool(row[11]) if len(row) > 11 else True
            os_val = row[12] if len(row) > 12 else None
            cpu = row[13] if len(row) > 13 else None
            ram = row[14] if len(row) > 14 else None
        else:
            # Order: active, os, cpu, ram, id, VPS, Password, IP, Provider, PLogin, PPassword, exim, squid, vpn, Notes
            active = _bool(row[0])
            os_val = row[1]
            cpu = row[2]
            ram = row[3]
            server_id = row[4]
            name = row[5]
            password = row[6]
            ip = row[7]
            provider = row[8]
            plogin = row[9]
            ppassword = row[10]
            has_exim = _bool(row[11])
            has_squid = _bool(row[12])
            has_vpn = _bool(row[13])
            notes = row[14] if len(row) > 14 else None

        if not name:
            skipped += 1
            continue

        # Pull details
        details = details_by_vps.get(server_id)
        website = details[1] if details and len(details) > 1 else None
        web_login = details[2] if details and len(details) > 2 else None
        web_pass = details[3] if details and len(details) > 3 else None
        vps_mgmt = details[4] if details and len(details) > 4 else None
        mgt_login = details[5] if details and len(details) > 5 else None
        mgt_pass = details[6] if details and len(details) > 6 else None

        server = Server(
            id=server_id,
            name=name,
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
            vps_management_url=vps_mgmt,
            mgt_login=mgt_login,
            mgt_pass=mgt_pass,
        )

        if dry_run:
            print(f'[dry-run] Would import server #{server_id} «{name}»')
        else:
            db.session.merge(server)
        created_servers += 1

    # Domains — legacy table column order: (domain_id, domain, vpsid)
    for row in domains_rows:
        if len(row) < 3:
            continue
        # Prefer the documented order: domain_id, domain, vpsid
        domain_name = row[1] if isinstance(row[1], str) else None
        vpsid = row[2] if isinstance(row[2], int) else None
        # Fallback heuristic if column order differs
        if not domain_name or not vpsid:
            for cell in row:
                if isinstance(cell, str) and '.' in cell and not domain_name:
                    domain_name = cell
                elif isinstance(cell, int) and vpsid is None and cell != row[0]:
                    vpsid = cell
        if not domain_name or not vpsid:
            continue
        if dry_run:
            print(f'[dry-run] Would import domain {domain_name} → server {vpsid}')
        else:
            db.session.add(Domain(domain=domain_name, server_id=vpsid))
        created_domains += 1

    if not dry_run:
        db.session.commit()

    print(f'\n✓ Imported: {created_servers} servers, {created_domains} domains, skipped {skipped}')
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
        import_legacy_data(tables, dry_run=args.dry_run, reset=args.reset)


if __name__ == '__main__':
    main()

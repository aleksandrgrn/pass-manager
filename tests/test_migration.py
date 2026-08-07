"""Тесты миграционного парсера .sql дампа (scripts/migrate_from_mysql.py).

Переписаны под настоящую схему старой базы (SHOW CREATE TABLE с боевого дампа,
specs/track-c-migrate-1-fix.md). Синтетический дамп — в формате mysqldump.

Порядок колонок `vps` (12 колонок):
    id, VPS, Login, Password, IP, Provider, PLogin, PPassword, exim, squid, vpn, Notes

Порядок `vps_details` (6 колонок):
    vps_id, active, os, cpu, ram, drive

Порядок `vps_management` (7 колонок):
    vps_id, website, web_login, web_pass, vps_management, mgt_login, mgt_pass

Порядок `domains` (3 колонки):
    domain_id, domain, vpsid      (vpsid — varchar, приводится к числу явно)
"""
from __future__ import annotations

import re
from unittest.mock import Mock

import pytest

from app.extensions import db
from app.models import Domain, Server, ServerGroup
from scripts.migrate_from_mysql import (
    import_legacy_data,
    parse_sql_dump,
)


# --------------------------------------------------------------------------- #
# Синтетический дамп
# --------------------------------------------------------------------------- #

SAMPLE_SQL = """
-- phpMyAdmin SQL Dump
-- version 5.0.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";

CREATE TABLE `vps` (
  `id` int(11) NOT NULL,
  `VPS` varchar(19) DEFAULT NULL,
  `Login` varchar(10) DEFAULT NULL,
  `Password` varchar(20) DEFAULT NULL,
  `IP` varchar(16) DEFAULT NULL,
  `Provider` varchar(32) DEFAULT NULL,
  `PLogin` varchar(60) DEFAULT NULL,
  `PPassword` varchar(60) DEFAULT NULL,
  `exim` varchar(4) DEFAULT NULL,
  `squid` varchar(5) DEFAULT NULL,
  `vpn` varchar(3) DEFAULT NULL,
  `Notes` varchar(86) DEFAULT NULL
);

INSERT INTO `vps` VALUES
(1, 'vps-alpha', 'admin', 'pass-alpha', '192.0.2.11', 'Hetzner', 'hlogin', 'hpp', '1', '0', '0', 'Mail relay'),
(2, 'vps-beta', '', 'pass-beta', '192.0.2.12', 'DigitalOcean', 'dlogin', 'dpp', '0', '1', '1', 'Squid+VPN'),
(3, '- old.example.com', 'root', 'pass-old', '192.0.2.13', NULL, NULL, NULL, NULL, NULL, NULL, NULL);

CREATE TABLE `vps_details` (
  `vps_id` int(11) NOT NULL,
  `active` int(11) DEFAULT NULL,
  `os` varchar(32) DEFAULT NULL,
  `cpu` varchar(64) DEFAULT NULL,
  `ram` varchar(32) DEFAULT NULL,
  `drive` varchar(32) DEFAULT NULL
);

INSERT INTO `vps_details` VALUES
(1, 1, 'Ubuntu 22.04', '2 vCPU', '4 GB', 'SSD 80 GB'),
(2, 1, 'Debian 12', '4 vCPU', '8 GB', '');

CREATE TABLE `vps_management` (
  `vps_id` int(11) NOT NULL,
  `website` varchar(64) DEFAULT NULL,
  `web_login` varchar(32) DEFAULT NULL,
  `web_pass` varchar(64) DEFAULT NULL,
  `vps_management` varchar(64) DEFAULT NULL,
  `mgt_login` varchar(64) DEFAULT NULL,
  `mgt_pass` varchar(64) DEFAULT NULL
);

INSERT INTO `vps_management` VALUES
(1, 'https://console.hetzner.com', 'hcloud', 'web-pass-1', 'https://mgmt.hetzner.com', 'admin', 'mgt-pass-1'),
(2, 'https://cloud.digitalocean.com', 'do-user', 'web-pass-2', NULL, NULL, NULL);

CREATE TABLE `domains` (
  `domain_id` int(11) NOT NULL,
  `domain` varchar(32) NOT NULL,
  `vpsid` varchar(32) NOT NULL
);

INSERT INTO `domains` VALUES
(101, 'alpha.example.com', '1'),
(102, 'mail.alpha.example.com', '1'),
(201, 'beta.example.org', '2');
"""


@pytest.fixture()
def sql_dump(tmp_path):
    """Создать временный .sql файл с синтетическим дампом и вернуть путь."""
    path = tmp_path / 'test_dump.sql'
    path.write_text(SAMPLE_SQL, encoding='utf-8')
    return path


# --------------------------------------------------------------------------- #
# parse_sql_dump
# --------------------------------------------------------------------------- #

class TestParseSqlDump:
    """Тесты парсера SQL-дампа."""

    def test_parses_all_tables(self, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        assert set(tables.keys()) == {'vps', 'vps_details', 'vps_management', 'domains'}

    def test_parses_three_servers(self, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        assert len(tables['vps']) == 3

    def test_parses_two_details(self, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        assert len(tables['vps_details']) == 2

    def test_parses_two_management(self, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        assert len(tables['vps_management']) == 2

    def test_parses_three_domains(self, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        assert len(tables['domains']) == 3

    def test_server_row_field_order(self, sql_dump):
        """Строка раскладывается по настоящему порядку (12 колонок)."""
        tables = parse_sql_dump(str(sql_dump))
        first = tables['vps'][0]
        assert first == [
            1, 'vps-alpha', 'admin', 'pass-alpha', '192.0.2.11', 'Hetzner',
            'hlogin', 'hpp', '1', '0', '0', 'Mail relay',
        ]

    def test_semicolon_inside_values_does_not_break_parsing(self, tmp_path):
        """`;` внутри Password/Notes не обрывает statement, записи из двух
        INSERT уцелели все (регрессия на дефект 1)."""
        sql = (
            "INSERT INTO `vps` VALUES "
            "(1, 'alpha;one', 'root', 'p;ass;word', '1.1.1.1', 'prov', 'l', 'pp', '1', '0', '0', 'note; with semicolons'),\n"
            "(2, 'beta', 'root', 'pass2', '2.2.2.2', 'prov2', 'l2', 'pp2', '0', '0', '0', 'second');\n"
            "INSERT INTO `vps` VALUES "
            "(3, 'gamma;', 'root', 'p3', '3.3.3.3', 'prov3', 'l3', 'pp3', '0', '0', '0', 'x');\n"
        )
        path = tmp_path / 'semi.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        assert len(tables['vps']) == 3
        rows = {r[0]: r for r in tables['vps']}
        # Пароль с ; сохранился целиком
        assert rows[1][3] == 'p;ass;word'
        assert rows[1][11] == 'note; with semicolons'
        # Вторая INSERT не потеряна, имя с ; уцелело
        assert rows[3][1] == 'gamma;'

    def test_handles_sql_with_quoted_strings_and_escapes(self, tmp_path):
        """Корректно обрабатываются экранированные апострофы (mysqldump, `\\'`)."""
        path = tmp_path / 'escapes.sql'
        path.write_text(
            "INSERT INTO `vps` VALUES "
            "(1, 'name with \\'quote\\' inside', 'root', 'p', '1.1.1.1', "
            "'prov', 'login', 'pp', '0', '0', '0', 'note');",
            encoding='utf-8',
        )
        tables = parse_sql_dump(str(path))
        assert tables['vps'][0][1] == "name with 'quote' inside"


# --------------------------------------------------------------------------- #
# import_legacy_data — dry-run
# --------------------------------------------------------------------------- #

class TestImportLegacyDryRun:
    """import_legacy_data с dry_run=True не должен писать в БД."""

    def test_dry_run_does_not_write(self, app, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        # Фикстура app уже создала пустую БД
        assert Server.query.count() == 0
        assert Domain.query.count() == 0

        with app.app_context():
            result = import_legacy_data(tables, dry_run=True)

        servers, domains, skipped = result
        assert servers == 3
        assert domains == 3
        assert skipped == 0
        # Но в БД пусто
        assert Server.query.count() == 0
        assert Domain.query.count() == 0


# --------------------------------------------------------------------------- #
# import_legacy_data — реальный импорт
# --------------------------------------------------------------------------- #

class TestImportLegacyReal:
    """import_legacy_data с dry_run=False должен записать данные."""

    def test_import_writes_servers_and_domains(self, app, sql_dump):
        tables = parse_sql_dump(str(sql_dump))

        with app.app_context():
            servers, domains, skipped = import_legacy_data(
                tables, dry_run=False, reset=True,
            )

        assert servers == 3
        assert domains == 3
        assert skipped == 0
        assert Server.query.count() == 3
        assert Domain.query.count() == 3

    def test_imported_server_has_correct_fields(self, app, sql_dump):
        """Основные поля + сервисные флаги (exim/squid/vpn — varchar)."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)

            srv1 = db.session.get(Server, 1)
            assert srv1 is not None
            assert srv1.name == 'vps-alpha'
            assert srv1.ip_address == '192.0.2.11'
            assert srv1.provider == 'Hetzner'
            assert srv1.ssh_username == 'admin'
            assert srv1.active is True
            # exim='1' → True, squid/vpn='0' → False
            assert srv1.has_exim is True
            assert srv1.has_squid is False
            assert srv1.has_vpn is False

            srv2 = db.session.get(Server, 2)
            assert srv2.has_squid is True
            assert srv2.has_vpn is True
            assert srv2.has_exim is False

    def test_empty_login_defaults_to_root(self, app, sql_dump):
        """Пустой Login → ssh_username='root' (поле NOT NULL, дефолт root)."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)
            srv2 = db.session.get(Server, 2)
            assert srv2.ssh_username == 'root'

    def test_panel_fields_from_management_and_hw_from_details(self, app, sql_dump):
        """os/cpu/ram приходят из vps_details, а website/web_login/mgt_* из
        vps_management. Тест падает, если таблицы поменять местами."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)

            srv1 = db.session.get(Server, 1)
            assert srv1.os == 'Ubuntu 22.04'
            assert srv1.cpu == '2 vCPU'
            assert srv1.ram == '4 GB'
            assert srv1.website == 'https://console.hetzner.com'
            assert srv1.web_login == 'hcloud'
            assert srv1.web_pass == 'web-pass-1'
            assert srv1.vps_management_url == 'https://mgmt.hetzner.com'
            assert srv1.mgt_login == 'admin'
            assert srv1.mgt_pass == 'mgt-pass-1'

    def test_drive_appended_to_notes(self, app, sql_dump):
        """Непустой `drive` дописывается в notes строкой «Диск: …»; пустой —
        notes не трогает."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)

            srv1 = db.session.get(Server, 1)
            assert srv1.notes == 'Mail relay\nДиск: SSD 80 GB'

            # srv2: drive='' → notes без изменений
            srv2 = db.session.get(Server, 2)
            assert srv2.notes == 'Squid+VPN'

    def test_dash_name_marks_inactive(self, app, sql_dump):
        """Имя с тире в начале → active=False, тире и пробелы срезаются."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)

            srv3 = db.session.get(Server, 3)
            assert srv3 is not None
            assert srv3.name == 'old.example.com'
            assert srv3.active is False

    def test_imported_domains_link_to_servers(self, app, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)

            srv1 = db.session.get(Server, 1)
            srv2 = db.session.get(Server, 2)
            assert srv1.domains.count() == 2
            assert srv2.domains.count() == 1

    def test_domains_vpsid_as_string_binds_and_non_numeric_skipped(self, app, tmp_path):
        """vpsid varchar: '7' привязывается к серверу 7, нечисловое значение
        пропускается с подсчётом."""
        sql = (
            "CREATE TABLE `vps` (`id` int, `VPS` varchar(19), `Login` varchar(10), "
            "`Password` varchar(20), `IP` varchar(16), `Provider` varchar(32), "
            "`PLogin` varchar(60), `PPassword` varchar(60), `exim` varchar(4), "
            "`squid` varchar(5), `vpn` varchar(3), `Notes` varchar(86));\n"
            "INSERT INTO `vps` VALUES "
            "(7, 'srv-7', 'root', 'p', '1.1.1.7', 'prov', 'l', 'pp', '0', '0', '0', 'n');\n"
            "CREATE TABLE `domains` (`domain_id` integer, `domain` varchar(32), `vpsid` varchar(32));\n"
            "INSERT INTO `domains` VALUES "
            "(1, 'seven.example.com', '7'),\n"
            "(2, 'bad.example.com', 'abc');\n"
        )
        path = tmp_path / 'dom.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        with app.app_context():
            servers, domains, skipped = import_legacy_data(tables, dry_run=True)

        assert servers == 1
        assert domains == 1  # привязан только '7'; 'abc' пропущен

    @pytest.mark.parametrize('exim_raw,squid_raw,vpn_raw,expected_services', [
        ('1', '0', '0', ['exim']),
        ('0', '1', '1', ['squid', 'vpn']),
        ('1', '1', '1', ['exim', 'squid', 'vpn']),
        ('0', '0', '0', []),
    ])
    def test_services_toggles_parsed_correctly(
        self, app, tmp_path, exim_raw, squid_raw, vpn_raw, expected_services,
    ):
        """Сервисные флаги из legacy (varchar) должны превращаться в bool правильно."""
        sql = (
            "INSERT INTO `vps` VALUES "
            f"(1, 'srv', 'root', 'pass', '1.1.1.1', 'prov', 'login', 'pp', "
            f"{exim_raw}, {squid_raw}, {vpn_raw}, 'note');"
        )
        path = tmp_path / 'svc.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)
            srv = db.session.get(Server, 1)
            assert srv.services_list == expected_services

    def test_reset_clears_existing_data(self, app, sql_dump):
        """reset=True должен удалить старые записи перед импортом."""
        with app.app_context():
            # Создаём старые записи
            db.session.add(Server(id=500, name='old-server'))
            db.session.add(Domain(domain='old.example.com', server_id=500))
            db.session.commit()
            assert Server.query.count() == 1

            tables = parse_sql_dump(str(sql_dump))
            import_legacy_data(tables, dry_run=False, reset=True)

            # Старая запись удалена, новые добавлены
            assert db.session.get(Server, 500) is None
            assert Server.query.count() == 3


# --------------------------------------------------------------------------- #
# import_legacy_data — параметр --group
# --------------------------------------------------------------------------- #

class TestImportLegacyGroup:
    """Группа для переносимых серверов (FIX DEPLOY.1, правка B)."""

    def test_without_group_leaves_servers_groupless(self, app, sql_dump):
        """Без --group поведение прежнее: group_id остаётся None."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)
            assert ServerGroup.query.count() == 0
            assert all(
                srv.group_id is None for srv in Server.query.all()
            ), 'Без --group серверы не должны получать группу'

    def test_import_creates_missing_group(self, app, sql_dump):
        """Группа создаётся, если её нет; серверы получают её id."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True, group='Связь')

            groups = ServerGroup.query.all()
            assert len(groups) == 1
            assert groups[0].name == 'Связь'
            assert all(
                srv.group_id == groups[0].id for srv in Server.query.all()
            )

    def test_import_reuses_existing_group(self, app, sql_dump):
        """Существующая группа переиспользуется, новая не создаётся."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            existing = ServerGroup(name='Связь')
            db.session.add(existing)
            db.session.commit()

            import_legacy_data(tables, dry_run=False, reset=True, group='Связь')

            assert ServerGroup.query.count() == 1
            assert all(
                srv.group_id == existing.id for srv in Server.query.all()
            )

    def test_dry_run_with_group_writes_nothing(self, app, sql_dump):
        """dry_run с группой ничего не пишет: ни серверов, ни группы."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=True, group='Связь')

            assert ServerGroup.query.count() == 0
            assert Server.query.count() == 0
            assert Domain.query.count() == 0

    def test_broken_row_does_not_leak_password(self, app, tmp_path, capsys):
        """Битая строка печатает предупреждение, но не значение пароля."""
        sql = (
            "INSERT INTO `vps` VALUES "
            "(1, 'broken', 'secret-pass');"
        )
        path = tmp_path / 'broken.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        with app.app_context():
            import_legacy_data(tables, dry_run=True)

        out = capsys.readouterr().out
        # Предупреждение о неверном числе колонок в выводе ЕСТЬ
        assert 'vps row has 3 columns instead of 12' in out
        # Значение пароля в выводе ОТСУТСТВУЕТ.
        assert 'secret-pass' not in out


# --------------------------------------------------------------------------- #
# Отчёт --dry-run
# --------------------------------------------------------------------------- #

class TestDryRunReport:
    """Итоговый отчёт: разбивка пропусков и счётчиков, без значений полей."""

    def test_report_breakdown_counts(self, app, sql_dump, capsys):
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=True)

        out = capsys.readouterr().out
        assert 'vps: parsed 3, created 3, skipped 0 (wrong columns: 0, empty name: 0)' in out
        assert 'inactive by dash: 1' in out
        assert 'domains: parsed 3, bound 3, ' \
               'skipped by vpsid: 0, empty name: 0, '\
               'orphan (no created server): 0, wrong column count: 0' in out
        assert 'notes with disk: 1' in out

    def test_report_does_not_print_password_values(self, app, sql_dump, capsys):
        """Отчёт и предупреждения не печатают значения полей (пароли)."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=True)

        out = capsys.readouterr().out
        assert 'pass-alpha' not in out
        assert 'pass-beta' not in out


# --------------------------------------------------------------------------- #
# Домены: сироты, пустое имя, инвариант отчёта (FIX-MIGRATE-2)
# --------------------------------------------------------------------------- #

_ORPHAN_SQL_VPS = (
    "CREATE TABLE `vps` (`id` int, `VPS` varchar(19), `Login` varchar(10), "
    "`Password` varchar(20), `IP` varchar(16), `Provider` varchar(32), "
    "`PLogin` varchar(60), `PPassword` varchar(60), `exim` varchar(4), "
    "`squid` varchar(5), `vpn` varchar(3), `Notes` varchar(86));\n"
    "INSERT INTO `vps` VALUES "
    "(1, 'srv-1', 'root', 'p', '1.1.1.1', 'prov', 'l', 'pp', '0', '0', '0', 'n');\n"
)

_DOMAINS_SQL = (
    "CREATE TABLE `domains` (`domain_id` int, `domain` varchar(32), `vpsid` varchar(32));\n"
    "INSERT INTO `domains` VALUES "
)


def _domain_report(out):
    """Вернуть dict со счётчиками доменов из строки отчёта 'domains: …'."""
    line = next(
        l for l in out.splitlines()
        if l.strip().startswith('domains:')
    )
    pattern = (
        r'parsed (\d+), bound (\d+), '
        r'skipped by vpsid: (\d+), empty name: (\d+), '
        r'orphan \(no created server\): (\d+), wrong column count: (\d+)'
    )
    m = re.search(pattern, line)
    assert m, f'не удалось распарсить строку отчёта: {line!r}'
    return {
        'parsed': int(m.group(1)),
        'bound': int(m.group(2)),
        'vpsid': int(m.group(3)),
        'empty': int(m.group(4)),
        'orphan': int(m.group(5)),
        'len': int(m.group(6)),
    }


def _vps_report(out):
    """Вернуть (parsed, created, skipped) из строки отчёта про vps."""
    line = next(
        l for l in out.splitlines()
        if l.strip().startswith('vps: parsed')
    )
    m = re.search(r'vps: parsed (\d+), created (\d+), skipped (\d+)', line)
    assert m, f'нет строки отчёта по vps: {line!r}'
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


class TestDomainsOrphan:
    """Домен, чей vpsid не указывает на реально созданный сервер, не переносится."""

    def test_domain_to_deleted_server_not_imported(self, app, tmp_path):
        """vpsid указывает на сервер, которого нет в дампе → сирота, не создаём."""
        sql = (
            _ORPHAN_SQL_VPS
            + _DOMAINS_SQL
            + "(1, 'alpha.example.com', '1'),\n"    # валидный → привязывается
            + "(2, 'ghost.example.com', '99');\n"   # сервера 99 в дампе нет → сирота
        )
        path = tmp_path / 'orphan1.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        with app.app_context():
            servers, domains, _ = import_legacy_data(tables, dry_run=False, reset=True)

        assert servers == 1
        assert domains == 1                                   # привязан только alpha
        assert Domain.query.count() == 1
        assert db.session.query(Domain).filter_by(server_id=1).count() == 1
        assert db.session.query(Domain).filter_by(server_id=99).count() == 0

    def test_domain_to_skipped_server_not_imported(self, app, tmp_path, capsys):
        """vpsid указывает на сервер, пропущенный из-за пустого имени → сирота."""
        sql = (
            "CREATE TABLE `vps` (`id` int, `VPS` varchar(19), `Login` varchar(10), "
            "`Password` varchar(20), `IP` varchar(16), `Provider` varchar(32), "
            "`PLogin` varchar(60), `PPassword` varchar(60), `exim` varchar(4), "
            "`squid` varchar(5), `vpn` varchar(3), `Notes` varchar(86));\n"
            # сервер с пустым именем → пропускается
            "INSERT INTO `vps` VALUES "
            "(50, '', 'root', 'p', '1.1.1.1', 'prov', 'l', 'pp', '0', '0', '0', 'n');\n"
            + _DOMAINS_SQL
            + "(1, 'hang.example.com', '50');\n"
        )
        path = tmp_path / 'orphan2.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        with app.app_context():
            import_legacy_data(tables, dry_run=True)

        out = capsys.readouterr().out
        report = _domain_report(out)
        assert report['parsed'] == 1
        assert report['bound'] == 0
        assert report['orphan'] == 1          # сервера 50 создано не будет

    def test_empty_name_domain_is_counted(self, app, tmp_path, capsys):
        """Домен с пустым именем учитывается своим счётчиком, а не теряется."""
        sql = (
            _ORPHAN_SQL_VPS
            + _DOMAINS_SQL
            + "(1, '', '1');\n"                 # пустое имя → свой счётчик
        )
        path = tmp_path / 'emptyname.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        with app.app_context():
            import_legacy_data(tables, dry_run=True)

        out = capsys.readouterr().out
        report = _domain_report(out)
        assert report['parsed'] == 1
        assert report['bound'] == 0
        assert report['empty'] == 1
        # строка не «пропала»: числится в разбивке → отчёт сходится
        assert (
            report['parsed']
            == report['bound'] + report['vpsid'] + report['empty']
            + report['orphan'] + report['len']
        )


class TestReportReconciles:
    """Инварианты отчёта: ни одна строка не исчезает без счётчика (FIX-MIGRATE-2)."""

    def test_domains_report_reconciles_all_kinds(self, app, tmp_path, capsys):
        """bound + все счётчики отброшенных == len(domains_rows).

        Дамп со всеми видами потери сразу. Ассерт через счётчики, а не через
        магические числа: новый необсчитанный continue уронит равенство.
        """
        sql = (
            _ORPHAN_SQL_VPS
            + _DOMAINS_SQL
            + "(1, 'ok.example.com', '1'),\n"       # bound
            + "(2, 'ghost.example.com', '99'),\n"   # orphan: сервера нет в дампе
            + "(3, 'bad.example.com', 'abc'),\n"    # vpsid не число
            + "(4, '', '1'),\n"                     # пустое имя
            + "(5);\n"                              # короткая строка (len<3)
        )
        path = tmp_path / 'inv_domains.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        assert len(tables['domains']) == 5
        with app.app_context():
            import_legacy_data(tables, dry_run=True)

        out = capsys.readouterr().out
        report = _domain_report(out)
        assert report['parsed'] == 5
        # Инвариант: bound + все счётчики отброшенных == разобрано.
        # Новый необсчитанный continue уменьшит правую сумму — равенство падёт.
        assert (
            report['bound'] + report['vpsid'] + report['empty']
            + report['orphan'] + report['len'] == report['parsed']
        )

    def test_vps_report_reconciles(self, app, tmp_path, capsys):
        """created + skipped == len(vps_rows)."""
        sql = (
            _ORPHAN_SQL_VPS
            # пустое имя → skip
            + "INSERT INTO `vps` VALUES "
            "(2, '', 'root', 'p2', '1.1.1.2', 'p', 'l', 'pp', '0', '0', '0', 'n');\n"
            # неверное число колонок → skip
            + "INSERT INTO `vps` VALUES (7, 'x');\n"
        )
        path = tmp_path / 'inv_vps.sql'
        path.write_text(sql, encoding='utf-8')

        tables = parse_sql_dump(str(path))
        assert len(tables['vps']) == 3
        with app.app_context():
            import_legacy_data(tables, dry_run=True)

        out = capsys.readouterr().out
        parsed, created, skipped = _vps_report(out)
        assert parsed == 3
        assert created == 1
        assert skipped == 2
        assert created + skipped == parsed


# --------------------------------------------------------------------------- #
# Порядок в конце import_legacy_data (FIX-MIGRATE-3)
# --------------------------------------------------------------------------- #

class LyingList(list):
    """Изображает строку, исчезнувшую не увеличив ни один счётчик."""

    def __len__(self):
        return super().__len__() + 1


class TestReportPrintedBeforeCommit:
    """При расхождении отчёт уже напечатан, а коммит ещё не делался.

    Порядок в конце import_legacy_data: посчитать → напечатать отчёт →
    проверить сходимость (raise при расхождении) → только потом commit
    (FIX-MIGRATE-3).
    """

    def test_mismatch_prints_report_and_skips_commit(self, app, monkeypatch, capsys):
        """LyingList врёт про длину: счётчики не сходятся, отчёт на экране,
        commit не вызван."""
        tables = {'vps': [], 'domains': LyingList()}
        commit = Mock()
        monkeypatch.setattr(db.session, 'commit', commit)

        with app.app_context():
            with pytest.raises(RuntimeError):
                import_legacy_data(tables, dry_run=False)

        out = capsys.readouterr().out
        # Отчёт напечатан до проверки: строка про domains есть в выводе.
        assert 'domains: parsed 1' in out
        # Коммита не было: расхождение — в базу ничего не ушло.
        commit.assert_not_called()

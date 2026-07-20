"""Тесты миграционного парсера .sql дампа (scripts/migrate_from_mysql.py).

Синтетический дамп построен по формату mysqldump:
    INSERT INTO `<table>` VALUES (...), (...);

Порядок колонок `vps` (id-first, 15 колонок):
    id, name, password, ip, provider, plogin, ppassword,
    exim, squid, vpn, notes, active, os, cpu, ram

Порядок `vps_details` (7 колонок):
    vps_id, website, web_login, web_pass,
    vps_management, mgt_login, mgt_pass

Порядок `domains` (3 колонки):
    domain_id, domain, vpsid
"""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import Domain, Server
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
  `VPS` varchar(200) NOT NULL,
  `Password` varchar(200) DEFAULT NULL,
  `IP` varchar(45) DEFAULT NULL,
  `Provider` varchar(200) DEFAULT NULL,
  `PLogin` varchar(200) DEFAULT NULL,
  `PPassword` varchar(200) DEFAULT NULL,
  `exim` tinyint(1) NOT NULL DEFAULT 0,
  `squid` tinyint(1) NOT NULL DEFAULT 0,
  `vpn` tinyint(1) NOT NULL DEFAULT 0,
  `Notes` text,
  `active` tinyint(1) NOT NULL DEFAULT 1,
  `os` varchar(128) DEFAULT NULL,
  `cpu` varchar(128) DEFAULT NULL,
  `ram` varchar(64) DEFAULT NULL
);

INSERT INTO `vps` VALUES
(1, 'vps-alpha', 'pass-alpha', '192.0.2.11', 'Hetzner', 'root', 'pp-alpha', 1, 0, 0, 'Mail relay', 1, 'Ubuntu 22.04', '2 vCPU', '4 GB'),
(2, 'vps-beta',  'pass-beta',  '192.0.2.12', 'DigitalOcean', 'root', 'pp-beta', 0, 1, 1, 'Squid+VPN', 1, 'Debian 12', '4 vCPU', '8 GB');

CREATE TABLE `vps_details` (
  `vps_id` int(11) NOT NULL,
  `website` varchar(255) DEFAULT NULL,
  `web_login` varchar(255) DEFAULT NULL,
  `web_pass` varchar(255) DEFAULT NULL,
  `vps_management` varchar(255) DEFAULT NULL,
  `mgt_login` varchar(255) DEFAULT NULL,
  `mgt_pass` varchar(255) DEFAULT NULL
);

INSERT INTO `vps_details` VALUES
(1, 'https://console.hetzner.com', 'hcloud', 'web-pass-1', 'https://mgmt.hetzner.com', 'admin', 'mgt-pass-1'),
(2, 'https://cloud.digitalocean.com', 'do-user', 'web-pass-2', NULL, NULL, NULL);

CREATE TABLE `domains` (
  `domain_id` int(11) NOT NULL,
  `domain` varchar(256) NOT NULL,
  `vpsid` int(11) NOT NULL
);

INSERT INTO `domains` VALUES
(101, 'alpha.example.com', 1),
(102, 'mail.alpha.example.com', 1),
(201, 'beta.example.org', 2);
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
        assert set(tables.keys()) == {'vps', 'vps_details', 'domains'}

    def test_parses_two_servers(self, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        assert len(tables['vps']) == 2

    def test_parses_two_details(self, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        assert len(tables['vps_details']) == 2

    def test_parses_three_domains(self, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        assert len(tables['domains']) == 3

    def test_server_row_fields_parsed_correctly(self, sql_dump):
        """Парсер должен корректно разбивать строку на значения."""
        tables = parse_sql_dump(str(sql_dump))
        first = tables['vps'][0]
        # id-first, 15 колонок
        assert first[0] == 1
        assert first[1] == 'vps-alpha'
        assert first[2] == 'pass-alpha'
        assert first[3] == '192.0.2.11'
        assert first[4] == 'Hetzner'
        # exim/squid/vpn — числовые из дампа
        assert first[7] == 1
        assert first[8] == 0
        assert first[9] == 0

    def test_handles_sql_with_quoted_strings_and_escapes(self, tmp_path):
        """Парсер корректно обрабатывает экранированные апострофы."""
        path = tmp_path / 'escapes.sql'
        path.write_text(
            "INSERT INTO `vps` VALUES "
            "(1, 'name with \\'quote\\' inside', 'p', '1.1.1.1', "
            "'prov', 'login', 'pp', 0, 0, 0, 'note', 1, NULL, NULL, NULL);",
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

        # Метод вернул счётчики планируемых записей
        servers, domains, skipped = result
        assert servers == 2
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

        assert servers == 2
        assert domains == 3
        assert skipped == 0
        assert Server.query.count() == 2
        assert Domain.query.count() == 3

    def test_imported_server_has_correct_fields(self, app, sql_dump):
        """Проверяем основные поля + services toggles."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)

            srv1 = db.session.get(Server, 1)
            assert srv1 is not None
            assert srv1.name == 'vps-alpha'
            assert srv1.ip_address == '192.0.2.11'
            assert srv1.provider == 'Hetzner'
            # exim=1 → True
            assert srv1.has_exim is True
            assert srv1.has_squid is False
            assert srv1.has_vpn is False
            assert srv1.active is True

            srv2 = db.session.get(Server, 2)
            assert srv2.has_squid is True
            assert srv2.has_vpn is True
            assert srv2.has_exim is False

    def test_imported_server_has_vps_details(self, app, sql_dump):
        """website/web_login/... подцепляются из vps_details по vps_id."""
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)

            srv1 = db.session.get(Server, 1)
            assert srv1.website == 'https://console.hetzner.com'
            assert srv1.web_login == 'hcloud'
            assert srv1.mgt_login == 'admin'

    def test_imported_domains_link_to_servers(self, app, sql_dump):
        tables = parse_sql_dump(str(sql_dump))
        with app.app_context():
            import_legacy_data(tables, dry_run=False, reset=True)

            srv1 = db.session.get(Server, 1)
            srv2 = db.session.get(Server, 2)
            assert srv1.domains.count() == 2
            assert srv2.domains.count() == 1

    @pytest.mark.parametrize('exim_raw,squid_raw,vpn_raw,expected_services', [
        (1, 0, 0, ['exim']),
        (0, 1, 1, ['squid', 'vpn']),
        (1, 1, 1, ['exim', 'squid', 'vpn']),
        (0, 0, 0, []),
    ])
    def test_services_toggles_parsed_correctly(
        self, app, tmp_path, exim_raw, squid_raw, vpn_raw, expected_services,
    ):
        """Сервисные флаги из legacy должны превращаться в bool правильно."""
        sql = (
            "INSERT INTO `vps` VALUES "
            f"(1, 'srv', 'pass', '1.1.1.1', 'prov', 'login', 'pp', "
            f"{exim_raw}, {squid_raw}, {vpn_raw}, 'note', 1, NULL, NULL, NULL);"
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
            assert Server.query.count() == 2

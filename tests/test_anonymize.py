"""Тесты скрипта обезличивания копии базы (scripts/anonymize_db.py).

Тесты на настоящей схеме проекта и настоящем файле — без моков. Временная
база создаётся схемой проекта через db.metadata.create_all, а скрипт
запускается как реальный процесс (subprocess), чтобы проверять код возврата.
"""
from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.extensions import db
from app.models import Domain, Server
import app.models  # noqa: F401 — регистрирует таблицы в db.metadata

from scripts.anonymize_db import SENSITIVE_COLUMNS

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'anonymize_db.py'

# Девять колонок, которые обязаны обнуляться. Держим локально, а не из
# константы скрипта, чтобы тест 2 ловил пропавшую колонку (мутация снимает
# `notes` из константы скрипта — обнуляться перестаёт, тест должен это
# заметить). Спецификация требует именно девять.
EXPECTED_SENSITIVE_COLUMNS = (
    'password_encrypted',
    'provider_password_encrypted',
    'web_pass_encrypted',
    'mgt_pass_encrypted',
    'password_pending_encrypted',
    'provider_login',
    'web_login',
    'mgt_login',
    'notes',
)


def _create_source_db(path: Path, with_domains: bool = True) -> None:
    """Создать базу настоящей схемой проекта и наполнить секретами."""
    engine = create_engine(f'sqlite:///{path}')
    db.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        for num, (name, ip) in enumerate(
            (('vps-test-01', '192.0.2.11'), ('vps-test-02', '192.0.2.12')),
            start=1,
        ):
            server = Server(name=name, ip_address=ip)
            for col in EXPECTED_SENSITIVE_COLUMNS:
                setattr(server, col, f'secret-{name}-{num}')
            session.add(server)
            session.flush()
            if with_domains:
                session.add(Domain(domain='alpha.example.com', server_id=server.id))
        session.commit()
    # Закрыть соединения пула: WAL-журнал (включается приложением) схлопывается
    # в основной файл. Иначе данные лежат в source.db-wal, а copy2 скопирует
    # пустой основной файл — как если бы копировали работающую базу.
    engine.dispose()


def _run_script(source: Path, copy: Path):
    """Запустить скрипт как процесс и вернуть CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(source), str(copy)],
        capture_output=True, text=True,
    )


def _sensitive_values(path: Path) -> list[list[str | None]]:
    """Вернуть значения секретных колонок всех серверов базы."""
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            f'SELECT {", ".join(EXPECTED_SENSITIVE_COLUMNS)} FROM servers ORDER BY id',
        ).fetchall()
    finally:
        conn.close()
    return [list(row) for row in rows]


def _server_names_ips(path: Path) -> list[tuple[str | None, str | None]]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            'SELECT name, ip_address FROM servers ORDER BY id',
        ).fetchall()
    finally:
        conn.close()
    return [tuple(row) for row in rows]


def _counts(path: Path) -> tuple[int, int]:
    conn = sqlite3.connect(path)
    try:
        servers = conn.execute('SELECT COUNT(*) FROM servers').fetchone()[0]
        domains = conn.execute('SELECT COUNT(*) FROM domains').fetchone()[0]
    finally:
        conn.close()
    return servers, domains


# --------------------------------------------------------------------------- #
# Тесты
# --------------------------------------------------------------------------- #

class TestAnonymizeColumns:
    def test_all_nine_columns_exist_in_model(self):
        """Каждое имя из константы скрипта есть в модели Server.

        Ловит переименование поля в модели: без этого теста скрипт молча
        перестанет чистить то, чего уже нет, и копия приедет с паролями.
        """
        model_columns = set(Server.__table__.columns.keys())
        assert SENSITIVE_COLUMNS, 'Константа скрипта не должна быть пустой'
        for name in SENSITIVE_COLUMNS:
            assert name in model_columns, f'Колонка {name} отсутствует в модели'


class TestAnonymizeRun:
    def test_secrets_cleared_in_copy(self, tmp_path):
        """После прогона в копии все девять полей NULL у обоих серверов."""
        source = tmp_path / 'source.db'
        copy = tmp_path / 'copy.db'
        _create_source_db(source)
        assert any(v is not None for row in _sensitive_values(source) for v in row)

        result = _run_script(source, copy)
        assert result.returncode == 0, result.stderr

        for row in _sensitive_values(copy):
            assert row == [None] * len(EXPECTED_SENSITIVE_COLUMNS)

    def test_data_not_lost(self, tmp_path):
        """Число строк servers/domains и name/ip_address сохраняются."""
        source = tmp_path / 'source.db'
        copy = tmp_path / 'copy.db'
        _create_source_db(source)
        expected_counts = _counts(source)
        expected_names_ips = _server_names_ips(source)

        result = _run_script(source, copy)
        assert result.returncode == 0, result.stderr

        assert _counts(copy) == expected_counts
        assert _server_names_ips(copy) == expected_names_ips

    def test_source_not_touched(self, tmp_path):
        """После прогона в исходной базе все девять полей на месте."""
        source = tmp_path / 'source.db'
        copy = tmp_path / 'copy.db'
        _create_source_db(source)
        before = _sensitive_values(source)

        result = _run_script(source, copy)
        assert result.returncode == 0, result.stderr

        assert _sensitive_values(source) == before

    def test_live_wal_connection_has_fresh_data(self, tmp_path):
        """Копия базы с активным соединением в WAL-режиме содержит свежие данные.

        Воспроизводит бой: приложение держит соединение открытым, свежие
        страницы лежат в <база>-wal, а не в основном файле. Файловое
        копирование тогда снимает пустую базу; backup() обязан учесть WAL.
        Проверяем наличие именно дописанного третьего сервера, а не «хоть
        что-то»: два первых сервера после dispose() внутри _create_source_db
        лежат в основном файле и попали бы в копию старым способом.
        """
        source = tmp_path / 'source.db'
        copy = tmp_path / 'copy.db'
        _create_source_db(source)

        # Своё соединение, не закрытое до конца теста — как работающее приложение.
        live_conn = sqlite3.connect(source)
        try:
            live_conn.execute('PRAGMA journal_mode=WAL')
            live_conn.execute(
                "INSERT INTO servers (name, ip_address, ssh_username, active, "
                "has_exim, has_squid, has_vpn, provisioning_status) "
                "VALUES ('vps-test-live', '192.0.2.99', 'root', 1, 0, 0, 0, 'ready')",
            )
            live_conn.commit()

            result = _run_script(source, copy)
            assert result.returncode == 0, result.stderr

            servers, _ = _counts(copy)
            assert servers == 3
            names_ips = _server_names_ips(copy)
            assert ('vps-test-live', '192.0.2.99') in names_ips
        finally:
            # Закрыть висящее соединение, чтобы падение теста не оставило
            # живых -wal/-shm файлов и не мешало tmp_path-очистке.
            live_conn.close()


class TestAnonymizeFailures:
    def test_refuses_same_path(self, tmp_path):
        """Источник и копия — один файл: ненулевой код, исходник не изменён."""
        source = tmp_path / 'same.db'
        _create_source_db(source)
        before = _sensitive_values(source)

        result = _run_script(source, source)
        assert result.returncode != 0
        # Причина отказа — именно совпадение путей, а не «копия уже
        # существует»: иначе тест зеленел бы и без этой проверки (случай
        # перекрывался бы соседней ошибкой), и мутация бы его не ловила.
        assert 'один и тот же файл' in result.stderr
        assert _sensitive_values(source) == before

    def test_refuses_existing_copy(self, tmp_path):
        """Копия уже существует: существующий файл не перезаписан."""
        source = tmp_path / 'source.db'
        copy = tmp_path / 'copy.db'
        _create_source_db(source)
        copy.write_bytes(b'ORIGINAL CONTENT')

        result = _run_script(source, copy)
        assert result.returncode != 0
        assert copy.read_bytes() == b'ORIGINAL CONTENT'

#!/usr/bin/env python3
"""Обезличить копию базы pass-manager.

Скрипт сам копирует исходный SQLite-файл, затем по копии одним UPDATE
обнуляет секретные поля таблицы `servers`. Исходник открывается только на
чтение при копировании — писать в боевую базу скрипт не может в принципе.
Копия снимается средствами SQLite (`Connection.backup()`), а не файловым
копированием, поэтому работающему приложению (WAL-журнал) скрипт не мешает.

Использование:
    ./venv/bin/python scripts/anonymize_db.py <исходная-база> <файл-копии>

Только стандартная библиотека: Flask/SQLAlchemy здесь не нужны — работаем
с произвольным файлом, а конфигурация приложения указывает на свою базу.
"""
import argparse
import os
import sqlite3
import sys

# Колонки таблицы `servers`, значения которых — секреты или свободный текст
# (в notes регулярно попадают пароли). Всё остальное (имена, адреса, связи)
# сохраняется: на нём и ловится сшивка импорта.
SENSITIVE_COLUMNS = (
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


def anonymize_db(source_path, copy_path):
    """Скопировать source_path в copy_path и обнулить секреты в копии.

    Возвращает (servers_processed, domains_left) для итогового отчёта.
    Бросает ValueError на некорректных путях — вывод остаётся за main().
    """
    if not os.path.exists(source_path):
        raise ValueError(f'Исходный файл не существует: {source_path}')
    if os.path.realpath(source_path) == os.path.realpath(copy_path):
        raise ValueError('Исходный файл и файл копии — один и тот же файл')
    if os.path.exists(copy_path):
        raise ValueError(f'Файл копии уже существует: {copy_path}')

    # Консистентный снимок живой базы средствами SQLite: read-only источник,
    # чтобы в него не ушло ни одной записи (без mode=ro SQLite вправе
    # выполнить восстановительный checkpoint и записать в боевую базу).
    # backup() учитывает WAL-журнал работающего приложения.
    source_conn = sqlite3.connect(f'file:{source_path}?mode=ro', uri=True)
    try:
        copy_conn = sqlite3.connect(copy_path)
        try:
            source_conn.backup(copy_conn)
        finally:
            copy_conn.close()
    finally:
        source_conn.close()

    assignments = ', '.join(f'{col} = NULL' for col in SENSITIVE_COLUMNS)
    conn = sqlite3.connect(copy_path)
    try:
        cur = conn.execute(f'UPDATE servers SET {assignments}')
        servers_processed = cur.rowcount
        domains_left = conn.execute('SELECT COUNT(*) FROM domains').fetchone()[0]
        conn.commit()
    finally:
        conn.close()
    return servers_processed, domains_left


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Скопировать SQLite-базу и обнулить секреты в копии',
    )
    parser.add_argument('source', help='путь к исходной базе (только чтение)')
    parser.add_argument('copy', help='путь к файлу копии (не должен существовать)')
    args = parser.parse_args(argv)

    try:
        servers_processed, domains_left = anonymize_db(args.source, args.copy)
    except ValueError as exc:
        print(f'✗ {exc}', file=sys.stderr)
        sys.exit(1)

    print(f'servers processed: {servers_processed}')
    print(f'domains left: {domains_left}')


if __name__ == '__main__':
    main()

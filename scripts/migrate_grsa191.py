"""Миграция истории изменений сервера (GRSA-191): таблицы server_changes и
server_change_items.

Создаёт таблицы, если их нет: db.create_all() трогает только отсутствующие
таблицы, существующие не переписывает. Колонок в старые таблицы не добавляет.
История начинается с момента выкатки — задним числом ничего не заполняется.

Idempotent: повторный прогон безопасен — второй запуск обязан ничего
не менять.

Usage:
    python scripts/migrate_grsa191.py            # применить миграцию
    python scripts/migrate_grsa191.py --dry-run  # только отчёт, без записи
"""
import argparse
import os
import sys

# Добавляем корень проекта в sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect

from app import create_app
from app.extensions import db

TABLES = ('server_changes', 'server_change_items')


def migrate(dry_run: bool) -> list:
    """Возвращает таблицы, которые пришлось (или пришлось бы) создать."""
    existing = set(inspect(db.engine).get_table_names())
    missing = [t for t in TABLES if t not in existing]
    if missing and not dry_run:
        db.create_all()
    return missing


def main():
    parser = argparse.ArgumentParser(description='История изменений сервера: таблицы.')
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Только показать, что было бы сделано (без записи в БД).',
    )
    args = parser.parse_args()

    config_name = os.environ.get('FLASK_CONFIG', 'development')
    app = create_app(config_name)

    with app.app_context():
        mode = 'DRY-RUN' if args.dry_run else 'APPLY'
        print(f'== Миграция истории изменений ({mode}) ==')
        missing = migrate(dry_run=args.dry_run)
        for table in TABLES:
            print(f'Таблица {table}: ' + ('создаём' if table in missing else 'уже есть'))
        if args.dry_run:
            print('\nЗапустите без --dry-run, чтобы применить изменения.')


if __name__ == '__main__':
    main()

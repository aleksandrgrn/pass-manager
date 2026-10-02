"""Миграция окна файлов (SFTP): таблица журнала file_access_log.

Создаёт таблицу, если её нет: db.create_all() трогает только отсутствующие
таблицы, существующие не переписывает. Колонок в старые таблицы не добавляет.

Idempotent: повторный прогон безопасен — второй запуск обязан ничего
не менять.

Usage:
    python scripts/migrate_sftp.py            # применить миграцию
    python scripts/migrate_sftp.py --dry-run  # только отчёт, без записи
"""
import argparse
import os
import sys

# Добавляем корень проекта в sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect

from app import create_app
from app.extensions import db

TABLE = 'file_access_log'


def migrate(dry_run: bool) -> bool:
    """Возвращает True, если таблицу пришлось (или пришлось бы) создать."""
    if TABLE in inspect(db.engine).get_table_names():
        return False
    if not dry_run:
        db.create_all()
    return True


def main():
    parser = argparse.ArgumentParser(description='Окно файлов: таблица журнала.')
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
        print(f'== Миграция окна файлов ({mode}) ==')
        created = migrate(dry_run=args.dry_run)
        print(f'Таблица {TABLE}: ' + ('создаём' if created else 'уже есть'))
        if args.dry_run:
            print('\nЗапустите без --dry-run, чтобы применить изменения.')


if __name__ == '__main__':
    main()

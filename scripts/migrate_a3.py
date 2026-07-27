"""Track C A3.1 миграция: три колонки Server для pipeline онбординга.

Добавляет (если их ещё нет — проверка через PRAGMA table_info(servers)):
  - vps_manager_server_id  INTEGER
  - provisioning_status    VARCHAR(20) NOT NULL DEFAULT 'ready'
  - bootstrap_request_id   VARCHAR(64)

DEFAULT 'ready' в ALTER TABLE ADD COLUMN автоматически проставляет значение
существующим строкам (поведение SQLite) — отдельный UPDATE не нужен.

Idempotent: повторный прогон безопасен.

Usage:
    python scripts/migrate_a3.py            # применить миграцию
    python scripts/migrate_a3.py --dry-run  # только отчёт, без записи
"""
import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import List

# Добавляем корень проекта в sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from app import create_app
from app.extensions import db

# (имя колонки, DDL-тип для ADD COLUMN)
NEW_COLUMNS = (
    ('vps_manager_server_id', 'INTEGER'),
    ('provisioning_status', "VARCHAR(20) NOT NULL DEFAULT 'ready'"),
    ('bootstrap_request_id', 'VARCHAR(64)'),
    ('ssh_port', 'INTEGER'),
)


@dataclass
class MigrationStats:
    """Сводная статистика миграции."""
    columns_added: List[str] = field(default_factory=list)
    columns_already_present: List[str] = field(default_factory=list)

    def report(self) -> str:
        return (
            f'Колонок добавлено:  {len(self.columns_added)} {self.columns_added}\n'
            f'Уже существовали:   {len(self.columns_already_present)} {self.columns_already_present}'
        )


def _existing_columns() -> set:
    """Имена колонок таблицы servers (PRAGMA table_info)."""
    rows = db.session.execute(text('PRAGMA table_info(servers)')).fetchall()
    return {row[1] for row in rows}  # row[1] = name


def migrate(dry_run: bool) -> MigrationStats:
    stats = MigrationStats()
    existing = _existing_columns()

    for column_name, ddl in NEW_COLUMNS:
        if column_name in existing:
            stats.columns_already_present.append(column_name)
            continue

        print(f'  • servers.{column_name}: добавляем ({ddl})')
        stats.columns_added.append(column_name)
        if not dry_run:
            db.session.execute(text(f'ALTER TABLE servers ADD COLUMN {column_name} {ddl}'))

    if not dry_run and stats.columns_added:
        db.session.commit()

    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Track C A3.1: добавить колонки онбординга в Server.'
    )
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
        print(f'== Track C A3.1 миграция ({mode}) ==')

        stats = migrate(dry_run=args.dry_run)
        print('\n' + stats.report())

        if args.dry_run:
            print('\nЗапустите без --dry-run, чтобы применить изменения.')


if __name__ == '__main__':
    main()

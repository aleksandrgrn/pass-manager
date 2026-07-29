"""Track C B1 миграция: группы серверов и членство.

Создаёт:
  - таблицу server_groups
  - таблицу server_group_memberships
  - колонку servers.group_id (INTEGER, nullable) + индекс на неё

Таблицы поднимаются через db.create_all() — он трогает только отсутствующие,
существующие не переписывает. Колонка добавляется вручную: create_all() уже
созданную таблицу не меняет.

Idempotent: повторный прогон безопасен.

Usage:
    python scripts/migrate_b1.py            # применить миграцию
    python scripts/migrate_b1.py --dry-run  # только отчёт, без записи
"""
import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import List

# Добавляем корень проекта в sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect, text

from app import create_app
from app.extensions import db

NEW_TABLES = ('server_groups', 'server_group_memberships')

# (имя колонки, DDL-тип для ADD COLUMN)
NEW_COLUMNS = (
    ('group_id', 'INTEGER'),
)

# (имя индекса, колонка таблицы servers)
NEW_INDEXES = (
    ('ix_servers_group_id', 'group_id'),
)


@dataclass
class MigrationStats:
    """Сводная статистика миграции."""
    tables_created: List[str] = field(default_factory=list)
    tables_already_present: List[str] = field(default_factory=list)
    columns_added: List[str] = field(default_factory=list)
    columns_already_present: List[str] = field(default_factory=list)
    indexes_created: List[str] = field(default_factory=list)
    indexes_already_present: List[str] = field(default_factory=list)

    def report(self) -> str:
        return (
            f'Таблиц создано:     {len(self.tables_created)} {self.tables_created}\n'
            f'Уже существовали:   {len(self.tables_already_present)} {self.tables_already_present}\n'
            f'Колонок добавлено:  {len(self.columns_added)} {self.columns_added}\n'
            f'Уже существовали:   {len(self.columns_already_present)} {self.columns_already_present}\n'
            f'Индексов создано:   {len(self.indexes_created)} {self.indexes_created}\n'
            f'Уже существовали:   {len(self.indexes_already_present)} {self.indexes_already_present}'
        )


def _existing_columns() -> set:
    """Имена колонок таблицы servers (PRAGMA table_info)."""
    rows = db.session.execute(text('PRAGMA table_info(servers)')).fetchall()
    return {row[1] for row in rows}  # row[1] = name


def _existing_indexes() -> set:
    """Имена индексов таблицы servers (PRAGMA index_list)."""
    rows = db.session.execute(text('PRAGMA index_list(servers)')).fetchall()
    return {row[1] for row in rows}  # row[1] = name


def migrate(dry_run: bool) -> MigrationStats:
    stats = MigrationStats()

    # 1. Таблицы
    existing_tables = set(inspect(db.engine).get_table_names())
    for table_name in NEW_TABLES:
        if table_name in existing_tables:
            stats.tables_already_present.append(table_name)
        else:
            print(f'  • таблица {table_name}: создаём')
            stats.tables_created.append(table_name)

    if not dry_run and stats.tables_created:
        # create_all() создаёт только отсутствующие таблицы
        db.create_all()

    # 2. Колонка servers.group_id
    existing_columns = _existing_columns()
    for column_name, ddl in NEW_COLUMNS:
        if column_name in existing_columns:
            stats.columns_already_present.append(column_name)
            continue

        print(f'  • servers.{column_name}: добавляем ({ddl})')
        stats.columns_added.append(column_name)
        if not dry_run:
            db.session.execute(text(f'ALTER TABLE servers ADD COLUMN {column_name} {ddl}'))

    # 3. Индекс на неё. Отдельным шагом: ALTER TABLE ADD COLUMN индекс не создаёт,
    #    а на нём держится фильтр видимости из app/access/rules.py.
    existing_indexes = _existing_indexes()
    for index_name, column_name in NEW_INDEXES:
        if index_name in existing_indexes:
            stats.indexes_already_present.append(index_name)
            continue

        print(f'  • индекс {index_name}: создаём')
        stats.indexes_created.append(index_name)
        if not dry_run:
            db.session.execute(
                text(f'CREATE INDEX {index_name} ON servers ({column_name})')
            )

    if not dry_run and (stats.columns_added or stats.indexes_created):
        db.session.commit()

    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Track C B1: группы серверов, членство, Server.group_id.'
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
        print(f'== Track C B1 миграция ({mode}) ==')

        stats = migrate(dry_run=args.dry_run)
        print('\n' + stats.report())

        if args.dry_run:
            print('\nЗапустите без --dry-run, чтобы применить изменения.')


if __name__ == '__main__':
    main()

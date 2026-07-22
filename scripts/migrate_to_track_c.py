"""Track C A1 migration.

1. User.role: 'pass-admin'/'pass-lead'/'pass-user' -> 'admin'
   (local admin / break-glass user -> 'superadmin' если username ==
   LOCAL_ADMIN_USERNAME и is_local=True).
2. Server.has_exim/has_squid/has_vpn -> ServerService records (status='unknown').
   (FIX-7: мигрированные сервисы не авто-installing, только probe).
3. Создать ServiceTemplate records для exim/squid/vpn (если их ещё нет).

Idempotent: повторный прогон безопасен.

Usage:
    python scripts/migrate_to_track_c.py            # применить миграцию
    python scripts/migrate_to_track_c.py --dry-run  # только отчёт, без записи
"""
import argparse
import os
import sys
from dataclasses import dataclass

# Добавляем корень проекта в sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models import Server, ServerService, ServiceTemplate, User

# Старые роли -> новая роль (все мержатся в 'admin', см. таблицу в plan-A1 §1)
LEGACY_ROLES = ('pass-admin', 'pass-lead', 'pass-user')

# has_exim/has_squid/has_vpn -> имя ServiceTemplate
SERVICE_FIELDS = (
    ('has_exim', 'exim', 'Exim'),
    ('has_squid', 'squid', 'Squid'),
    ('has_vpn', 'vpn', 'VPN'),
)


@dataclass
class MigrationStats:
    """Сводная статистика миграции."""
    users_migrated: int = 0
    services_migrated: int = 0
    templates_created: int = 0

    def report(self) -> str:
        return (
            f'Пользователей мигрировано: {self.users_migrated}\n'
            f'ServerService создано:     {self.services_migrated}\n'
            f'ServiceTemplate создано:   {self.templates_created}'
        )


def _migrate_users(app, dry_run: bool) -> int:
    """Мигрировать role пользователей на 2-рольную модель."""
    count = 0
    local_admin_username = app.config.get('LOCAL_ADMIN_USERNAME', 'admin')

    for user in User.query.all():
        if user.role not in LEGACY_ROLES:
            continue

        if user.is_local and user.username == local_admin_username:
            new_role = 'superadmin'
        else:
            new_role = 'admin'

        print(f'  • user#{user.id} {user.username}: role {user.role!r} -> {new_role!r}')
        if not dry_run:
            user.role = new_role
        count += 1

    return count


def _get_or_create_template(name: str, display_name: str, dry_run: bool, stats: MigrationStats):
    """Найти существующий ServiceTemplate или создать новый (не commit-ит)."""
    template = ServiceTemplate.query.filter_by(name=name).first()
    if template:
        return template
    print(f'  • ServiceTemplate создан: {name}')
    stats.templates_created += 1
    if dry_run:
        return None
    template = ServiceTemplate(name=name, display_name=display_name)
    db.session.add(template)
    db.session.flush()  # получить template.id без commit
    return template


def _migrate_services(dry_run: bool, stats: MigrationStats) -> int:
    """Server.has_exim/has_squid/has_vpn -> ServerService(status='unknown')."""
    count = 0

    for field, name, display_name in SERVICE_FIELDS:
        servers_with_service = Server.query.filter(getattr(Server, field).is_(True)).all()
        if not servers_with_service:
            continue

        template = _get_or_create_template(name, display_name, dry_run, stats)

        for server in servers_with_service:
            if not dry_run:
                exists = ServerService.query.filter_by(
                    server_id=server.id, service_id=template.id,
                ).first()
                if exists:
                    continue

            print(f'  • server#{server.id} {name}: ServerService(status=unknown) создан')
            count += 1

            if not dry_run:
                db.session.add(ServerService(
                    server_id=server.id,
                    service_id=template.id,
                    status='unknown',
                ))

    return count


def migrate(app, dry_run: bool) -> MigrationStats:
    stats = MigrationStats()
    stats.users_migrated = _migrate_users(app, dry_run)
    stats.services_migrated = _migrate_services(dry_run, stats)

    if not dry_run:
        db.session.commit()

    return stats


def main():
    parser = argparse.ArgumentParser(description='Track C A1: миграция ролей и сервисов.')
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
        print(f'== Track C A1 миграция ({mode}) ==')

        stats = migrate(app, dry_run=args.dry_run)
        print('\n' + stats.report())

        if args.dry_run:
            print('\nЗапустите без --dry-run, чтобы применить изменения.')


if __name__ == '__main__':
    main()

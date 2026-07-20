"""Разовая миграция существующих plaintext-паролей Server в зашифрованный формат.

Каждое из 4 полей (password, provider_password, web_pass, mgt_pass) проверяется:
если значение есть и не начинается с префикса `gAAAAA` (Fernet-токен),
оно шифруется текущим ENCRYPTION_KEY и сохраняется обратно в колонку *_encrypted.

Usage:
    python scripts/encrypt_existing_passwords.py            # зашифровать plaintext
    python scripts/encrypt_existing_passwords.py --dry-run  # только отчёт
    python scripts/encrypt_existing_passwords.py --force    # перешифровать даже токены
"""
import argparse
import os
import sys
from dataclasses import dataclass

# Добавляем корень проекта в sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models import Server
from app.security import FERNET_PREFIX, decrypt, encrypt, is_no_op_mode


# Список гибридных полей модели Server, подлежащих шифрованию.
# Каждый кортеж: (имя атрибута hybrid_property, имя колонки *_encrypted).
ENCRYPTED_FIELDS = (
    ('password', 'password_encrypted'),
    ('provider_password', 'provider_password_encrypted'),
    ('web_pass', 'web_pass_encrypted'),
    ('mgt_pass', 'mgt_pass_encrypted'),
)


@dataclass
class MigrationStats:
    """Сводная статистика миграции."""
    servers_total: int = 0
    encrypted_count: int = 0
    skipped_already_encrypted: int = 0
    skipped_empty: int = 0

    def report(self) -> str:
        return (
            f'Серверов обработано: {self.servers_total}\n'
            f'Полей зашифровано:   {self.encrypted_count}\n'
            f'Пропущено (уже зашифровано): {self.skipped_already_encrypted}\n'
            f'Пропущено (пустое):          {self.skipped_empty}'
        )


def migrate(dry_run: bool, force: bool) -> MigrationStats:
    """Проход по всем серверам и шифрование plaintext-паролей."""
    stats = MigrationStats()
    servers = Server.query.all()
    stats.servers_total = len(servers)

    for server in servers:
        for attr_name, column_name in ENCRYPTED_FIELDS:
            # Читаем напрямую из колонки (минуя hybrid getter,
            # который попытался бы расшифровать — а в plaintext нечего).
            raw_value = getattr(server, column_name)

            if raw_value is None or raw_value == '':
                stats.skipped_empty += 1
                continue

            if raw_value.startswith(FERNET_PREFIX) and not force:
                stats.skipped_already_encrypted += 1
                continue

            # В no-op режиме без ENCRYPTION_KEY шифровать нечем.
            # Важно: не записывать расшифрованный plaintext обратно в *_encrypted,
            # иначе теряем секрет. Поэтому пропускаем.
            if is_no_op_mode():
                print(
                    f'  ⚠ server#{server.id} {attr_name}: шифрование пропущено '
                    f'(нет ENCRYPTION_KEY)',
                    file=sys.stderr,
                )
                continue

            # При --force: сначала расшифровываем (распознаёт и legacy plaintext,
            # и Fernet-токены), затем шифруем заново текущим ключом.
            plaintext_value = decrypt(raw_value) if force else raw_value
            encrypted = encrypt(plaintext_value)

            action = 'would encrypt' if dry_run else 'encrypted'
            print(
                f'  • server#{server.id} {attr_name}: '
                f'{len(raw_value)} chars → {action}'
            )

            if not dry_run:
                setattr(server, column_name, encrypted)

            stats.encrypted_count += 1

    if not dry_run and stats.encrypted_count > 0:
        db.session.commit()

    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Зашифровать plaintext-пароли Server через Fernet.'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Только показать, что было бы сделано (без записи в БД).',
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Перешифровать даже значения, уже имеющие префикс gAAAAA.',
    )
    args = parser.parse_args()

    config_name = os.environ.get('FLASK_CONFIG', 'development')
    app = create_app(config_name)

    with app.app_context():
        if is_no_op_mode():
            print(
                '⚠ Внимание: ENCRYPTION_KEY не задан. Шифрование будет no-op '
                '(значения останутся plaintext).',
                file=sys.stderr,
            )
            if not args.dry_run:
                print(
                    'Запустите с --dry-run для отчёта или задайте ENCRYPTION_KEY.',
                    file=sys.stderr,
                )
                sys.exit(2)

        mode = 'DRY-RUN' if args.dry_run else 'APPLY'
        force_note = ' [FORCE]' if args.force else ''
        print(f'== Шифрование паролей ({mode}{force_note}) ==')

        stats = migrate(dry_run=args.dry_run, force=args.force)
        print('\n' + stats.report())

        if args.dry_run and stats.encrypted_count > 0:
            print('\nЗапустите без --dry-run, чтобы применить изменения.')


if __name__ == '__main__':
    main()

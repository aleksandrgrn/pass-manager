"""Track C, FIX-C1-1 + FIX-C1-2: подключение серверов к VPS Manager
(specs/track-c-C1-1-fix.md, specs/track-c-C1-2-fix.md).

Берёт сервер из базы pass-manager, заводит его в VPS Manager через
существующий маршрут E1 (app.services.vps_client.add_server) и запоминает
полученный vps_manager_server_id.

Боевой прогон делает пользователь. Скрипт проверяется только тестами на моках
(tests/test_connect_vps_manager.py) — живых машин не трогаем.

Usage:
    python scripts/connect_to_vps_manager.py --ids 1,5,6,7,8 --port 2233 [--dry-run]
"""
import argparse
import os
import sys
from collections import OrderedDict
from typing import Dict, List
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db
from app.models import Server
from app.services import vps_client

# Категории отчёта. Отбраковка — до всякой сети; остальное — по исходу вызова.
CAT_NO_SERVER = 'нет такого сервера'
CAT_ALREADY = 'уже подключён'
CAT_NO_ADDR = 'нет адреса'
CAT_NO_PASSWORD = 'нет root-пароля'
CAT_BAD_USER = 'негодный ssh_username'
CAT_DRY_RUN = 'прошли отбор (dry-run)'
CAT_CONNECTED = 'подключено'
CAT_UNREACHABLE = 'не достучались до машины'
CAT_DUPLICATE = 'дубль на стороне VPS Manager'
CAT_FAILED = 'достучались, но операция не удалась'
CAT_ERROR = 'сбой при обработке'


def _categories() -> Dict[str, list]:
    """Свежие категории отчёта в фиксированном порядке печати.

    Значения — списки записей (id, имя); в «достучались, но операция не
    удалась» и «сбой при обработке» — тройка (id, имя, message). Для «нет
    такого сервера» имя отсутствует (записи в базе нет).
    """
    return OrderedDict((c, []) for c in (
        CAT_NO_SERVER,
        CAT_ALREADY,
        CAT_NO_ADDR,
        CAT_NO_PASSWORD,
        CAT_BAD_USER,
        CAT_DRY_RUN,
        CAT_CONNECTED,
        CAT_UNREACHABLE,
        CAT_DUPLICATE,
        CAT_FAILED,
        CAT_ERROR,
    ))


def connect_servers(server_ids: List[int], port: int, dry_run: bool = False) -> Dict[str, list]:
    """Обрабатывает серверы по списку id и возвращает категории отчёта.

    Для каждого id по порядку:
      1. отбраковка до всякой сети (таблица из спецификации);
      2. сухой прогон -> категория «прошли отбор (dry-run)», без сети и базы;
      3. пустой bootstrap_request_id -> uuid4().hex, запись и КОММИТ до вызова:
         обрыв между вызовом и коммитом потерял бы идемпотентность — тот же
         приём, что password_pending в app/services/provisioning.py;
      4. vps_client.add_server(...) — category_ids не передаём;
      5. успех -> vps_manager_server_id + ssh_port (порт ТОЛЬКО при успехе),
         коммит, категория «подключено»; успех без server_id — категория
         «достучались, но операция не удалась», в базу ничего;
      6. отказ -> ничего в базу, категория по result['error_type'].

    Всё с шага 3 обёрнуто в try/except: исключение не убивает прогон —
    rollback, категория «сбой при обработке», цикл идёт дальше.

    Root-пароль не подставляется в строки вывода ни на одной ветке.
    """
    categories = _categories()

    for server_id in server_ids:
        server = db.session.get(Server, server_id)

        if server is None:
            categories[CAT_NO_SERVER].append((server_id, None))
            continue

        if server.vps_manager_server_id is not None:
            categories[CAT_ALREADY].append((server.id, server.name))
            continue

        if not server.ip_address:
            categories[CAT_NO_ADDR].append((server.id, server.name))
            continue

        if not server.password:
            categories[CAT_NO_PASSWORD].append((server.id, server.name))
            continue

        username = (server.ssh_username or '').strip()
        if not username or username == '-':
            categories[CAT_BAD_USER].append((server.id, server.name))
            continue

        if dry_run:
            print(f'[dry-run] подключили бы: #{server.id} «{server.name}» (порт {port})')
            categories[CAT_DRY_RUN].append((server.id, server.name))
            continue

        # id и имя нужны для записи в отчёт и ПОСЛЕ rollback (rollback истекает
        # объекты сессии) — захватываем до try.
        sid, sname = server.id, server.name

        try:
            # Коммит ДО сетевого вызова: повторный запуск переиспользует тот же id.
            if not server.bootstrap_request_id:
                server.bootstrap_request_id = uuid4().hex
                db.session.commit()

            result = vps_client.add_server(
                name=server.name,
                ip_address=server.ip_address,
                ssh_port=port,
                username=username,
                password=server.password,
                bootstrap_request_id=server.bootstrap_request_id,
            )

            if result.get('success'):
                result_server_id = result.get('server_id')
                if not result_server_id:
                    # Пустой id при success:true — тихая порча данных: NULL в
                    # vps_manager_server_id навсегда оставил бы сервер
                    # «подключённым». Ничего в базу не пишем.
                    categories[CAT_FAILED].append(
                        (sid, sname, 'VPS Manager вернул успех без server_id')
                    )
                    continue

                server.vps_manager_server_id = result_server_id
                server.ssh_port = port  # только при успехе
                db.session.commit()
                categories[CAT_CONNECTED].append((sid, sname))
                continue

            error_type = result.get('error_type')
            if error_type in ('connection_refused', 'timeout'):
                categories[CAT_UNREACHABLE].append((sid, sname))
            elif error_type == 'duplicate':
                categories[CAT_DUPLICATE].append((sid, sname))
            else:
                message = (result.get('message') or '').strip()
                categories[CAT_FAILED].append((sid, sname, message))
        except Exception as exc:
            db.session.rollback()
            categories[CAT_ERROR].append(
                (sid, sname, f'{type(exc).__name__}: {exc}')
            )

    return categories


def report_and_check(categories: Dict[str, list], expected_total: int) -> None:
    """Печатает отчёт по категориям, затем проверяет инвариант суммы.

    Порядок нерушим: сначала печать, потом RuntimeError. Защита, срабатывающая
    до вывода цифр, бесполезна ровно в том случае, ради которого заведена.
    """
    print('\nОтчёт:')
    for cat, entries in categories.items():
        if not entries:
            print(f'  {cat}: 0')
            continue
        print(f'  {cat}: {len(entries)}')
        for entry in entries:
            entry_id, entry_name = entry[0], entry[1]
            if len(entry) >= 3:
                print(f'    - #{entry_id} «{entry_name}»: {entry[2]}')
            elif entry_name:
                print(f'    - #{entry_id} «{entry_name}»')
            else:
                print(f'    - #{entry_id}')

    total = sum(len(v) for v in categories.values())
    if total != expected_total:
        raise RuntimeError(
            f'Инвариант суммы нарушен: обработано {expected_total} id, '
            f'по категориям разошлось {total}'
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Track C FIX-C1-1: подключение серверов к VPS Manager.',
    )
    parser.add_argument('--ids', required=True, help='Список id серверов через запятую')
    parser.add_argument('--port', type=int, default=2233, help='SSH-порт (по умолчанию 2233)')
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Только показать, что было бы сделано (без сети и без записи в БД).',
    )
    args = parser.parse_args()

    try:
        server_ids = [int(part.strip()) for part in args.ids.split(',') if part.strip()]
    except ValueError:
        parser.error('--ids должен быть списком целых чисел через запятую')
    if not server_ids:
        parser.error('--ids пуст')

    config_name = os.environ.get('FLASK_CONFIG', 'development')
    app = create_app(config_name)

    with app.app_context():
        mode = 'DRY-RUN' if args.dry_run else 'APPLY'
        print(f'== Подключение серверов к VPS Manager ({mode}) ==')

        categories = connect_servers(server_ids, port=args.port, dry_run=args.dry_run)
        report_and_check(categories, len(server_ids))

        if args.dry_run:
            print('\nЗапустите без --dry-run, чтобы выполнить подключение.')


if __name__ == '__main__':
    main()
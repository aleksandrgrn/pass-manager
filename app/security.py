"""Симметричное шифрование секретов на основе Fernet.

Обёртка над `cryptography.fernet.Fernet` для прозрачного шифрования полей
модели Server. Значения в БД хранятся в виде Fernet-токенов (стандартный
префикс `gAAAAA`), что позволяет отличать их от legacy-plaintext.

Поведение зависит от окружения:
  * production — отсутствие ENCRYPTION_KEY считается критической ошибкой;
  * development — если ключ не задан, логируется warning, функции работают
    как no-op (возвращают plaintext), чтобы не блокировать локальный запуск.
"""
from __future__ import annotations

import logging

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

logger = logging.getLogger(__name__)

# Стандартный префикс Fernet-токена в base64. Используется для отличия
# зашифрованных значений от незашифрованного plaintext (обратная совместимость).
FERNET_PREFIX = 'gAAAAA'


def _get_encryption_key() -> str:
    """Возвращает ENCRYPTION_KEY из конфигурации приложения.

    В development при отсутствии ключа возвращает пустую строку (no-op режим).
    В production поднимает RuntimeError.
    """
    return current_app.config.get('ENCRYPTION_KEY', '') or ''


def _is_encrypted(value: str) -> bool:
    """True, если значение похоже на Fernet-токен."""
    return bool(value) and value.startswith(FERNET_PREFIX)


def is_no_op_mode() -> bool:
    """True, если шифрование выключено (dev без ENCRYPTION_KEY)."""
    return not _get_encryption_key()


def _ensure_key_strict() -> str:
    """Строгая проверка наличия ключа для записи.

    В production отсутствие ключа — ошибка конфигурации.
    В development — no-op: шифрование пропускается.
    """
    key = _get_encryption_key()
    if key:
        return key

    env = current_app.config.get('ENV', 'development').lower()
    debug = bool(current_app.config.get('DEBUG', False))
    if env == 'production' or not debug:
        raise RuntimeError(
            'ENCRYPTION_KEY не задан: невозможно шифровать секреты в БД. '
            'Сгенерируйте ключ: '
            'python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )

    logger.warning(
        'ENCRYPTION_KEY не задан в dev-окружении: пароли хранятся '
        'в открытом виде. Это допустимо только для локальной разработки.'
    )
    return ''


def _is_plain_str(value: object) -> bool:
    """True, если value — это обычная строка, а не SQLAlchemy expression.

    Гибридные свойства модели могут обращаться к encrypt/decrypt на class-level,
    где вместо строки приходит Column/ColumnClause. В этом случае функции
    должны вернуть аргумент нетронутым, чтобы не сломать SQLAlchemy expression.
    """
    return isinstance(value, str)


def encrypt(plaintext: str | None) -> str | None:
    """Шифрует строку в Fernet-токен.

    * `None` и пустая строка возвращаются как есть (поле остаётся пустым).
    * В dev без ENCRYPTION_KEY — no-op: возвращает plaintext как есть.
    * Уже зашифрованные значения не перешифровываются (идемпотентность).
    * Нестроковые значения (например, SQL-выражения при class-level доступе
      гибридного свойства) возвращаются как есть — см. ``_is_plain_str``.
    """
    if not _is_plain_str(plaintext):
        return plaintext
    if plaintext == '':
        return plaintext

    # Идемпотентность: повторное шифрование токена не требуется.
    if _is_encrypted(plaintext):
        return plaintext

    key = _ensure_key_strict()
    if not key:
        # Dev no-op режим.
        return plaintext

    fernet = Fernet(key.encode('utf-8'))
    token = fernet.encrypt(plaintext.encode('utf-8'))
    return token.decode('utf-8')


def decrypt(token: str | None) -> str | None:
    """Расшифровывает Fernet-токен.

    * `None`/пустая строка возвращаются как есть.
    * Значения без префикса `gAAAAA` считаются legacy plaintext и
      возвращаются без расшифровки (обратная совместимость).
    * В dev без ENCRYPTION_KEY — no-op: возвращает значение как есть.
    * Нестроковые значения (например, SQL-выражения при class-level доступе
      гибридного свойства) возвращаются как есть — см. ``_is_plain_str``.
    """
    if not _is_plain_str(token):
        return token
    if token == '':
        return token

    # Legacy plaintext — пропускаем как есть.
    if not _is_encrypted(token):
        return token

    key = _get_encryption_key()
    if not key:
        # Dev no-op режим: даже если значение зашифровано, расшифровать нечем.
        # Возвращаем как есть — вызовущий код увидит токен (лучше, чем уронить
        # приложение), но в логах будет warning при старте.
        logger.warning(
            'Получено зашифрованное значение, но ENCRYPTION_KEY не задан. '
            'Расшифровка невозможна.'
        )
        return token

    fernet = Fernet(key.encode('utf-8'))
    try:
        return fernet.decrypt(token.encode('utf-8')).decode('utf-8')
    except InvalidToken as exc:
        # Ключ не совпадает с тем, которым шифровали.
        raise RuntimeError(
            'Не удалось расшифровать значение: неверный ENCRYPTION_KEY '
            'или повреждённые данные.'
        ) from exc

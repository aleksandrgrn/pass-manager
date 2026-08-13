import os
from dotenv import load_dotenv

# Project root is two levels up from this file (app/config.py → root)
PROJECT_ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
INSTANCE_DIR = os.path.join(PROJECT_ROOT, 'instance')

# Ensure instance dir exists (Flask requires it for SQLALCHEMY_DATABASE_URI)
os.makedirs(INSTANCE_DIR, exist_ok=True)

# Load .env from instance/ first, fallback to project root
for env_path in (os.path.join(INSTANCE_DIR, '.env'),
                 os.path.join(PROJECT_ROOT, '.env')):
    if os.path.exists(env_path):
        load_dotenv(env_path)
        break


def _resolve_sqlite_uri(env_value, default_filename):
    """Resolve a SQLite URI to an absolute path.

    Accepts both sqlite:////absolute/path and sqlite:///relative/path,
    and also bare paths. Relative paths are resolved against PROJECT_ROOT.
    """
    if not env_value:
        return 'sqlite:///' + os.path.join(INSTANCE_DIR, default_filename)

    # Bare path or relative 'sqlite:///...'
    if env_value.startswith('sqlite:///'):
        path = env_value[len('sqlite:///'):]
        # Four slashes = already absolute (sqlite:////abs/path)
        if env_value.startswith('sqlite:////'):
            return env_value
        if not os.path.isabs(path):
            path = os.path.join(PROJECT_ROOT, path)
        return 'sqlite:///' + path
    if env_value.startswith('sqlite:////'):
        return env_value
    if os.path.isabs(env_value):
        return 'sqlite:///' + env_value
    return 'sqlite:///' + os.path.join(PROJECT_ROOT, env_value)


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32).hex())
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Шифрование паролей в БД (Fernet). Сгенерировать:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', '')

    # Безопасность сессий и форм
    PERMANENT_SESSION_LIFETIME = 32400  # 9 часов: рабочий день + обед (в секундах)
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF-токен живёт 1 час

    # LDAP
    LDAP_SERVER = os.environ.get('LDAP_SERVER', '')
    LDAP_PORT = int(os.environ.get('LDAP_PORT', 389))
    LDAP_USE_SSL = os.environ.get('LDAP_USE_SSL', 'false').lower() == 'true'
    LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN', '')
    LDAP_USER_DN = os.environ.get('LDAP_USER_DN', 'OU=Users')
    LDAP_BIND_DN = os.environ.get('LDAP_BIND_DN', '')
    LDAP_BIND_PASSWORD = os.environ.get('LDAP_BIND_PASSWORD', '')
    LDAP_USER_SEARCH_FILTER = os.environ.get('LDAP_USER_SEARCH_FILTER', '(sAMAccountName={username})')
    # PEM с корневым сертификатом внутреннего УЦ. Пусто — используется системное
    # хранилище доверенных корней.
    LDAP_CA_CERT_FILE = os.environ.get('LDAP_CA_CERT_FILE', '')
    # Строка ciphers для OpenSSL. Нужна там, где внутренняя PKI на ключах слабее
    # 2048 бит: системный уровень безопасности 2 отвергает такую цепочку даже
    # при валидной подписи. Пусто — системные умолчания, ничего не понижаем.
    LDAP_TLS_CIPHERS = os.environ.get('LDAP_TLS_CIPHERS', '')

    # Local fallback admin
    LOCAL_ADMIN_USERNAME = os.environ.get('LOCAL_ADMIN_USERNAME', 'admin')
    LOCAL_ADMIN_PASSWORD = os.environ.get('LOCAL_ADMIN_PASSWORD', '')

    # Pagination
    # Больше размера парка (401 сервер на 2026-08-07), чтобы список был одной
    # страницей: отдел листает его сверху вниз, а шапка таблицы липкая. Блок
    # кнопок внизу рисуется под `pagination.pages > 1` и пропадает сам.
    ITEMS_PER_PAGE = 500

    # VPS Manager service-контракт (/api/svc, Track C A2)
    VPS_MANAGER_API_URL = os.environ.get('VPS_MANAGER_API_URL', 'http://127.0.0.1:5000/api/svc')
    VPS_MANAGER_SERVICE_TOKEN = os.environ.get('VPS_MANAGER_SERVICE_TOKEN', '')

    # Per-server root-ключи (Track C A3.2, FIX-2) — путь конфигурируем, без хардкода.
    ANSIBLE_KEYS_DIR = os.environ.get('ANSIBLE_KEYS_DIR', '/etc/pass-manager/ansible/keys')


class DevConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = _resolve_sqlite_uri(
        os.environ.get('DATABASE_URL'),
        'pass_manager_dev.db'
    )
    # В dev cookie может передаваться по HTTP (localhost)
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class ProdConfig(Config):
    """Production configuration."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = _resolve_sqlite_uri(
        os.environ.get('DATABASE_URL'),
        'pass_manager.db'
    )
    # В prod cookie всегда только по HTTPS, независимо от FLASK_ENV
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class TestingConfig(Config):
    """Configuration for the pytest suite.

    TESTING=True — это единственный легитимный bypass для
    _validate_prod_secrets (см. app/__init__.py). Используется во всех тестах,
    чтобы можно было поднимать app с пустым ENCRYPTION_KEY/слабым SECRET_KEY.
    """
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False


config = {
    'development': DevConfig,
    'production': ProdConfig,
    'testing': TestingConfig,
    'default': DevConfig,
}

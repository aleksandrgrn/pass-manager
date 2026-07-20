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
    
    # LDAP
    LDAP_SERVER = os.environ.get('LDAP_SERVER', '')
    LDAP_PORT = int(os.environ.get('LDAP_PORT', 389))
    LDAP_USE_SSL = os.environ.get('LDAP_USE_SSL', 'false').lower() == 'true'
    LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN', '')
    LDAP_USER_DN = os.environ.get('LDAP_USER_DN', 'OU=Users')
    LDAP_BIND_DN = os.environ.get('LDAP_BIND_DN', '')
    LDAP_BIND_PASSWORD = os.environ.get('LDAP_BIND_PASSWORD', '')
    LDAP_USER_SEARCH_FILTER = os.environ.get('LDAP_USER_SEARCH_FILTER', '(sAMAccountName={username})')
    
    # LDAP Groups -> Roles mapping
    LDAP_GROUP_ADMIN = os.environ.get('LDAP_GROUP_ADMIN', 'CN=pass-admin')
    LDAP_GROUP_LEAD = os.environ.get('LDAP_GROUP_LEAD', 'CN=pass-lead')
    LDAP_GROUP_USER = os.environ.get('LDAP_GROUP_USER', 'CN=pass-user')
    
    # Full DN for group membership checks
    LDAP_GROUP_ADMIN_DN = os.environ.get('LDAP_GROUP_ADMIN_DN', '')
    LDAP_GROUP_LEAD_DN = os.environ.get('LDAP_GROUP_LEAD_DN', '')
    LDAP_GROUP_USER_DN = os.environ.get('LDAP_GROUP_USER_DN', '')
    
    # Local fallback admin
    LOCAL_ADMIN_USERNAME = os.environ.get('LOCAL_ADMIN_USERNAME', 'admin')
    LOCAL_ADMIN_PASSWORD = os.environ.get('LOCAL_ADMIN_PASSWORD', '')
    
    # Pagination
    ITEMS_PER_PAGE = 50


class DevConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = _resolve_sqlite_uri(
        os.environ.get('DATABASE_URL'),
        'pass_manager_dev.db'
    )


class ProdConfig(Config):
    """Production configuration."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = _resolve_sqlite_uri(
        os.environ.get('DATABASE_URL'),
        'pass_manager.db'
    )


config = {
    'development': DevConfig,
    'production': ProdConfig,
    'default': DevConfig,
}

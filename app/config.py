import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, 'instance', '.env'))


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
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(basedir, 'instance', 'pass_manager_dev.db')
    )


class ProdConfig(Config):
    """Production configuration."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(basedir, 'instance', 'pass_manager.db')
    )


config = {
    'development': DevConfig,
    'production': ProdConfig,
    'default': DevConfig,
}

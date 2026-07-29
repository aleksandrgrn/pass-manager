"""LDAP authentication module."""
import logging
import socket
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from ldap3.core.exceptions import LDAPResponseTimeoutError, LDAPSocketReceiveError, LDAPSocketSendError
from ldap3.utils.conv import escape_filter_chars
import ssl

logger = logging.getLogger(__name__)

# Таймаут на любые LDAP-операции (в секундах).
# Если AD «висит», login не будет висеть дольше этого значения.
LDAP_RECEIVE_TIMEOUT = 10


def authenticate_ldap(username, password, app):
    """
    Authenticate user against Active Directory via LDAP.

    Returns:
        dict with keys: authenticated (bool), user_info (dict)
        or None if authentication fails (включая таймаут).
    """
    ldap_server = app.config.get('LDAP_SERVER')
    ldap_port = app.config.get('LDAP_PORT', 389)
    ldap_use_ssl = app.config.get('LDAP_USE_SSL', False)
    ldap_base_dn = app.config.get('LDAP_BASE_DN', '')
    ldap_user_dn = app.config.get('LDAP_USER_DN', 'OU=Users')
    ldap_bind_dn = app.config.get('LDAP_BIND_DN', '')
    ldap_bind_password = app.config.get('LDAP_BIND_PASSWORD', '')
    ldap_user_search_filter = app.config.get('LDAP_USER_SEARCH_FILTER', '(sAMAccountName={username})')
    ldap_ca_cert_file = app.config.get('LDAP_CA_CERT_FILE', '')

    if not ldap_server:
        logger.warning('LDAP_SERVER not configured')
        return None

    if not ldap_bind_dn:
        # Раньше здесь был режим прямого bind'а без служебной учётки. Он собирал
        # UPN как f'{username}@{base_dn}', то есть «ivanov@DC=company,DC=local» —
        # не валидный UPN, вход не работал никогда. Плюс не читал displayName.
        # Молча неработающий режим — ловушка; лучше явный отказ с объяснением.
        logger.error(
            'LDAP_BIND_DN не задан. Вход через AD требует служебной учётной записи: '
            'ею находят пользователя в каталоге, а пароль проверяется отдельным '
            'bind\'ом от имени самого пользователя.'
        )
        return None

    if not ldap_use_ssl:
        logger.warning(
            'LDAP настроен без SSL: простой bind по порту %s передаёт пароль '
            'пользователя открытым текстом. Включите LDAPS '
            '(LDAP_USE_SSL=true, LDAP_PORT=636).', ldap_port,
        )

    try:
        # Build server connection
        if ldap_use_ssl:
            # CERT_REQUIRED, а не CERT_NONE: без проверки сертификата шифрование
            # есть, а доверия нет — подставной контроллер домена спокойно примет
            # соединение и получит доменный пароль сотрудника. Пустой
            # LDAP_CA_CERT_FILE означает системное хранилище корней; для
            # внутреннего УЦ путь к его PEM обязателен.
            tls_config = Tls(
                validate=ssl.CERT_REQUIRED,
                ca_certs_file=ldap_ca_cert_file or None,
            )
            server = Server(
                ldap_server,
                port=ldap_port,
                use_ssl=True,
                tls=tls_config,
                receive_timeout=LDAP_RECEIVE_TIMEOUT,
            )
        else:
            server = Server(
                ldap_server,
                port=ldap_port,
                use_ssl=False,
                receive_timeout=LDAP_RECEIVE_TIMEOUT,
            )

        # First bind with service account to search for user
        bind_conn = Connection(
            server,
            user=ldap_bind_dn,
            password=ldap_bind_password,
            auto_bind=True,
            receive_timeout=LDAP_RECEIVE_TIMEOUT,
        )

        # Search for user
        # B5/F-004: экранируем спецсимволы LDAP-фильтра (инъекция через username)
        safe_username = escape_filter_chars(username)
        search_filter = ldap_user_search_filter.format(username=safe_username)
        search_base = f'{ldap_user_dn},{ldap_base_dn}' if ldap_user_dn else ldap_base_dn

        bind_conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'displayName', 'mail', 'dn']
        )

        if not bind_conn.entries:
            logger.info(f'LDAP user {username} not found')
            bind_conn.unbind()
            return None

        entry = bind_conn.entries[0]
        user_dn = entry.entry_dn
        display_name = str(entry.displayName) if hasattr(entry, 'displayName') else username

        bind_conn.unbind()

        # Now try to bind as the user to verify password
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=True,
            receive_timeout=LDAP_RECEIVE_TIMEOUT,
        )
        user_conn.unbind()

        return {
            'authenticated': True,
            'user_info': {
                'username': username,
                'display_name': display_name,
                'email': str(entry.mail) if hasattr(entry, 'mail') else None,
            },
        }

    except (LDAPResponseTimeoutError, LDAPSocketReceiveError, LDAPSocketSendError, socket.timeout) as e:
        # Таймаут LDAP — не валимся с 500, просто считаем попытку неудачной.
        # ldap3 не имеет единого «LDAPSocketTimeoutError»: таймауты приходят как
        # LDAPResponseTimeoutError (превышён receive_timeout) или как
        # LDAPSocketReceiveError/SendError, оборачивающие socket.timeout.
        logger.warning(
            'LDAP timeout для пользователя %s при обращении к %s:%s (%s)',
            username, ldap_server, ldap_port, e,
        )
        return None
    except Exception as e:
        logger.error(f'LDAP authentication error for {username}: {e}')
        return None

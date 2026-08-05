"""LDAP authentication module."""
import logging
import socket
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPResponseTimeoutError,
    LDAPSocketReceiveError,
    LDAPSocketSendError,
)
from ldap3.utils.conv import escape_filter_chars
import ssl

logger = logging.getLogger(__name__)

# Таймаут на любые LDAP-операции (в секундах).
# Если AD «висит», login не будет висеть дольше этого значения.
LDAP_RECEIVE_TIMEOUT = 10


class LdapUnavailable(Exception):
    """Каталог не смог ответить: это поломка, а не «пароль не подошёл».

    Ненастроенная или заблокированная служебная учётка, недоступный
    контроллер, непройденная проверка сертификата — всё это раньше
    возвращалось тем же тихим None, что и неверный пароль сотрудника, и
    приложение отвечало «неверный логин или пароль». После ротации пароля
    служебной учётки это сообщение получил бы весь отдел, и причину искали
    бы у себя, а не в `.env`.
    """


def authenticate_ldap(username, password, app):
    """
    Authenticate user against Active Directory via LDAP.

    Returns:
        dict with keys: authenticated (bool), user_info (dict)
        или None — если вход не состоялся по вине учётных данных: пользователя
        нет в каталоге (гейт по группе) или его пароль не подошёл.

    Raises:
        LdapUnavailable: каталог сломан или недоступен. Отличать обязательно —
            см. docstring исключения.
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
    ldap_tls_ciphers = app.config.get('LDAP_TLS_CIPHERS', '')

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
        raise LdapUnavailable('LDAP_BIND_DN не задан')

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
                # Понижение уровня нужно только под слабую внутреннюю PKI
                # (RSA-1024): системный уровень 2 отвергает её при валидной
                # подписи. Проверка цепочки при этом НЕ отключается — она
                # остаётся CERT_REQUIRED и привязана к ca_certs_file.
                ciphers=ldap_tls_ciphers or None,
            )
            server = Server(
                ldap_server,
                port=ldap_port,
                use_ssl=True,
                tls=tls_config,
                # У Server параметр называется connect_timeout; receive_timeout есть
                # только у Connection. Перепутанные местами, они стоили проекту
                # неработающего входа в AD от A1 до B1 — TypeError глотался
                # except'ом ниже, и функция молча возвращала None.
                connect_timeout=LDAP_RECEIVE_TIMEOUT,
            )
        else:
            server = Server(
                ldap_server,
                port=ldap_port,
                use_ssl=False,
                # У Server параметр называется connect_timeout; receive_timeout есть
                # только у Connection. Перепутанные местами, они стоили проекту
                # неработающего входа в AD от A1 до B1 — TypeError глотался
                # except'ом ниже, и функция молча возвращала None.
                connect_timeout=LDAP_RECEIVE_TIMEOUT,
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
            # 'dn' здесь быть не должно: у Server get_info=SCHEMA по умолчанию, ldap3
            # сверяет имена со схемой и бросает LDAPAttributeError на невалидное имя.
            # DN — свойство записи (entry.entry_dn ниже), а не атрибут AD.
            attributes=['sAMAccountName', 'displayName', 'mail']
        )

        if not bind_conn.entries:
            logger.info(f'LDAP user {username} not found')
            bind_conn.unbind()
            return None

        entry = bind_conn.entries[0]
        user_dn = entry.entry_dn
        display_name = str(entry.displayName) if hasattr(entry, 'displayName') else username

        bind_conn.unbind()

        # Now try to bind as the user to verify password.
        # Этот bind — единственное место, где invalidCredentials означает
        # «пароль сотрудника не подошёл». Служебный bind выше бросает ровно
        # такой же LDAPBindError, но означает поломку, поэтому два bind'а
        # разведены по отдельным except: сузить общий по типу исключения
        # нельзя — баг не исчезнет, а переедет.
        try:
            user_conn = Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=True,
                receive_timeout=LDAP_RECEIVE_TIMEOUT,
            )
        except LDAPBindError:
            logger.info('LDAP: пароль пользователя %s не подошёл', username)
            return None
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
        # Таймаут LDAP — не валимся с 500, но и за неверный пароль не выдаём.
        # ldap3 не имеет единого «LDAPSocketTimeoutError»: таймауты приходят как
        # LDAPResponseTimeoutError (превышён receive_timeout) или как
        # LDAPSocketReceiveError/SendError, оборачивающие socket.timeout.
        logger.warning(
            'LDAP timeout для пользователя %s при обращении к %s:%s (%s)',
            username, ldap_server, ldap_port, e,
        )
        raise LdapUnavailable(f'{ldap_server}:{ldap_port} не ответил') from e
    except Exception as e:
        # Сюда попадает всё, что случилось до bind'а пользователя: bind
        # служебной учётки, TLS, поиск. Это поломка нашей стороны.
        logger.error(f'LDAP authentication error for {username}: {e}')
        raise LdapUnavailable(str(e)) from e

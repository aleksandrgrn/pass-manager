"""LDAP authentication module."""
import logging
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
import ssl

logger = logging.getLogger(__name__)


def authenticate_ldap(username, password, app):
    """
    Authenticate user against Active Directory via LDAP.
    
    Returns:
        dict with keys: authenticated (bool), user_info (dict), role (str)
        or None if authentication fails.
    """
    ldap_server = app.config.get('LDAP_SERVER')
    ldap_port = app.config.get('LDAP_PORT', 389)
    ldap_use_ssl = app.config.get('LDAP_USE_SSL', False)
    ldap_base_dn = app.config.get('LDAP_BASE_DN', '')
    ldap_user_dn = app.config.get('LDAP_USER_DN', 'OU=Users')
    ldap_bind_dn = app.config.get('LDAP_BIND_DN', '')
    ldap_bind_password = app.config.get('LDAP_BIND_PASSWORD', '')
    ldap_user_search_filter = app.config.get('LDAP_USER_SEARCH_FILTER', '(sAMAccountName={username})')
    
    if not ldap_server:
        logger.warning('LDAP_SERVER not configured')
        return None

    try:
        # Build server connection
        if ldap_use_ssl:
            tls_config = Tls(validate=ssl.CERT_NONE)
            server = Server(ldap_server, port=ldap_port, use_ssl=True, tls=tls_config)
        else:
            server = Server(ldap_server, port=ldap_port, use_ssl=False)

        # First bind with service account to search for user
        if ldap_bind_dn:
            bind_conn = Connection(server, user=ldap_bind_dn, password=ldap_bind_password, auto_bind=True)
            
            # Search for user
            search_filter = ldap_user_search_filter.format(username=username)
            search_base = f'{ldap_user_dn},{ldap_base_dn}' if ldap_user_dn else ldap_base_dn
            
            bind_conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'displayName', 'mail', 'memberOf', 'dn']
            )
            
            if not bind_conn.entries:
                logger.info(f'LDAP user {username} not found')
                bind_conn.unbind()
                return None
            
            entry = bind_conn.entries[0]
            user_dn = entry.entry_dn
            display_name = str(entry.displayName) if hasattr(entry, 'displayName') else username
            member_of = entry.memberOf.values if hasattr(entry, 'memberOf') else []
            
            bind_conn.unbind()
            
            # Now try to bind as the user to verify password
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
            
            # Determine role from group membership
            role = _determine_role(member_of, app)
            
            return {
                'authenticated': True,
                'user_info': {
                    'username': username,
                    'display_name': display_name,
                    'email': str(entry.mail) if hasattr(entry, 'mail') else None,
                },
                'role': role,
            }
        else:
            # No bind DN — try direct bind with username
            user_dn = f'{username}@{ldap_base_dn}' if ldap_base_dn else username
            user_conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()
            
            return {
                'authenticated': True,
                'user_info': {
                    'username': username,
                    'display_name': username,
                },
                'role': 'pass-user',
            }

    except Exception as e:
        logger.error(f'LDAP authentication error for {username}: {e}')
        return None


def _determine_role(member_of, app):
    """Determine user role based on AD group membership."""
    # Normalize member_of to a list of strings
    groups = [str(g).lower() for g in member_of]
    
    admin_dn = app.config.get('LDAP_GROUP_ADMIN_DN', '').lower()
    lead_dn = app.config.get('LDAP_GROUP_LEAD_DN', '').lower()
    user_dn = app.config.get('LDAP_GROUP_USER_DN', '').lower()
    
    # Also check short CN names
    admin_cn = app.config.get('LDAP_GROUP_ADMIN', 'CN=pass-admin').lower()
    lead_cn = app.config.get('LDAP_GROUP_LEAD', 'CN=pass-lead').lower()
    
    for group in groups:
        if admin_dn and admin_dn in group:
            return 'pass-admin'
        if admin_cn and admin_cn in group:
            return 'pass-admin'
        if lead_dn and lead_dn in group:
            return 'pass-lead'
        if lead_cn and lead_cn in group:
            return 'pass-lead'
    
    # Default: pass-user
    return 'pass-user'

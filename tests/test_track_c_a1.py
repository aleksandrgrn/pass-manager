"""Track C A1: LDAP auth-only role handling + migration script tests."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.extensions import db
from app.models import ServerService, ServiceTemplate, User


# --------------------------------------------------------------------------- #
# LDAP = auth-only, роль не определяется через AD-группы
# --------------------------------------------------------------------------- #

class TestLdapAuthRoleHandling:
    """LDAP = auth-only, role не определяется через AD groups."""

    def test_first_ldap_login_creates_user_with_admin_role(self, app, client):
        app.config['LDAP_SERVER'] = 'ldap.example.com'
        fake_result = {
            'authenticated': True,
            'user_info': {'username': 'ldapuser1', 'display_name': 'LDAP User'},
        }
        with patch('app.auth.views.authenticate_ldap', return_value=fake_result):
            resp = client.post(
                '/auth/login',
                data={'username': 'ldapuser1', 'password': 'whatever'},
                environ_base={'REMOTE_ADDR': '198.51.100.20'},
            )
        assert resp.status_code == 302

        user = User.query.filter_by(username='ldapuser1').first()
        assert user is not None
        assert user.role == 'admin'

    def test_subsequent_login_preserves_promoted_role(self, app, client, db):
        # Существующий пользователь уже повышен до superadmin вручную.
        user = User(username='ldapuser2', display_name='LDAP User 2',
                    role='superadmin', is_local=False)
        db.session.add(user)
        db.session.commit()

        app.config['LDAP_SERVER'] = 'ldap.example.com'
        fake_result = {
            'authenticated': True,
            'user_info': {'username': 'ldapuser2', 'display_name': 'LDAP User 2'},
        }
        with patch('app.auth.views.authenticate_ldap', return_value=fake_result):
            resp = client.post(
                '/auth/login',
                data={'username': 'ldapuser2', 'password': 'whatever'},
                environ_base={'REMOTE_ADDR': '198.51.100.21'},
            )
        assert resp.status_code == 302

        refreshed = User.query.filter_by(username='ldapuser2').first()
        assert refreshed.role == 'superadmin'

    def test_get_or_create_user_does_not_overwrite_role(self, app):
        from app.auth.views import _get_or_create_user

        with app.app_context():
            user = User(username='directuser', role='superadmin', is_local=False)
            db.session.add(user)
            db.session.commit()

            result = _get_or_create_user(username='directuser', display_name='Direct User')
            assert result.role == 'superadmin'
            assert result.display_name == 'Direct User'


# --------------------------------------------------------------------------- #
# scripts/migrate_to_track_c.py — идемпотентность
# --------------------------------------------------------------------------- #

class TestMigrationScriptIdempotency:
    """scripts/migrate_to_track_c.py идемпотентен."""

    def _make_local_user(self, db, username, role, is_local=True):
        user = User(username=username, role=role, is_local=is_local)
        db.session.add(user)
        db.session.commit()
        return user

    def test_migrate_pass_admin_to_admin(self, app, db):
        from scripts.migrate_to_track_c import migrate
        self._make_local_user(db, 'u1', 'pass-admin', is_local=False)
        migrate(app, dry_run=False)
        assert User.query.filter_by(username='u1').first().role == 'admin'

    def test_migrate_pass_lead_to_admin(self, app, db):
        from scripts.migrate_to_track_c import migrate
        self._make_local_user(db, 'u2', 'pass-lead', is_local=False)
        migrate(app, dry_run=False)
        assert User.query.filter_by(username='u2').first().role == 'admin'

    def test_migrate_pass_user_to_admin(self, app, db):
        from scripts.migrate_to_track_c import migrate
        self._make_local_user(db, 'u3', 'pass-user', is_local=False)
        migrate(app, dry_run=False)
        assert User.query.filter_by(username='u3').first().role == 'admin'

    def test_migrate_local_admin_becomes_superadmin(self, app, db):
        """Break-glass: is_local + username == LOCAL_ADMIN_USERNAME -> superadmin."""
        from scripts.migrate_to_track_c import migrate
        local_admin_username = app.config['LOCAL_ADMIN_USERNAME']
        self._make_local_user(db, local_admin_username, 'pass-admin', is_local=True)
        migrate(app, dry_run=False)
        assert User.query.filter_by(username=local_admin_username).first().role == 'superadmin'

    def test_migrate_idempotent(self, app, db):
        from scripts.migrate_to_track_c import migrate
        self._make_local_user(db, 'u4', 'pass-user', is_local=False)

        stats1 = migrate(app, dry_run=False)
        stats2 = migrate(app, dry_run=False)

        assert stats1.users_migrated == 1
        assert stats2.users_migrated == 0  # второй прогон не находит legacy-ролей
        assert User.query.filter_by(username='u4').first().role == 'admin'

    def test_migrate_dry_run_no_changes(self, app, db):
        from scripts.migrate_to_track_c import migrate
        self._make_local_user(db, 'u5', 'pass-user', is_local=False)

        migrate(app, dry_run=True)

        assert User.query.filter_by(username='u5').first().role == 'pass-user'

    def test_migrate_has_exim_to_server_service(self, app, db):
        from app.models import Server
        from scripts.migrate_to_track_c import migrate

        server = Server(name='vps-with-exim', has_exim=True, has_squid=False, has_vpn=False)
        db.session.add(server)
        db.session.commit()

        stats = migrate(app, dry_run=False)

        assert stats.services_migrated == 1
        template = ServiceTemplate.query.filter_by(name='exim').first()
        assert template is not None
        service = ServerService.query.filter_by(server_id=server.id, service_id=template.id).first()
        assert service is not None
        assert service.status == 'unknown'

        # Идемпотентность: повторный прогон не создаёт дубликат ServerService.
        migrate(app, dry_run=False)
        count = ServerService.query.filter_by(server_id=server.id, service_id=template.id).count()
        assert count == 1

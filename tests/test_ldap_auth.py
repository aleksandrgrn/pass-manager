"""Вход через AD: настройки, от которых зависит безопасность пароля сотрудника.

Живого домена в тестах нет, поэтому проверяем то, что проверить без него можно:
какие настройки приложение отвергает и с каким TLS оно вообще идёт к контроллеру.
Именно здесь ошибка стоит дороже всего — через LDAP входят все сотрудники.
"""
from __future__ import annotations

import ssl
from unittest.mock import patch

from app.auth.ldap_auth import authenticate_ldap


def _configure(app, **overrides):
    app.config.update({
        'LDAP_SERVER': 'dc01.example.local',
        'LDAP_PORT': 636,
        'LDAP_USE_SSL': True,
        'LDAP_BASE_DN': 'DC=example,DC=local',
        'LDAP_USER_DN': 'OU=Users',
        'LDAP_BIND_DN': 'CN=svc,OU=Service,DC=example,DC=local',
        'LDAP_BIND_PASSWORD': 'bind-secret',
        'LDAP_CA_CERT_FILE': '',
        **overrides,
    })


class TestRefusesUnusableConfig:
    """Неработающая настройка должна отказывать вслух, а не молча."""

    def test_no_server_returns_none(self, app):
        _configure(app, LDAP_SERVER='')
        assert authenticate_ldap('ivanov', 'pw', app) is None

    def test_no_bind_dn_returns_none(self, app, caplog):
        """Раньше здесь был режим прямого bind'а, собиравший невалидный UPN
        вида «ivanov@DC=example,DC=local». Он не работал никогда и молчал об этом."""
        _configure(app, LDAP_BIND_DN='')

        with patch('app.auth.ldap_auth.Connection') as conn:
            assert authenticate_ldap('ivanov', 'pw', app) is None
            # к домену вообще не пошли — отказ до сетевого вызова
            conn.assert_not_called()

        assert 'LDAP_BIND_DN' in caplog.text


class TestCertificateIsVerified:
    """Сертификат контроллера домена проверяется всегда.

    Без проверки шифрование есть, а доверия нет: подставной сервер примет
    соединение и получит доменный пароль сотрудника.
    """

    def test_tls_requires_valid_certificate(self, app):
        _configure(app)

        with patch('app.auth.ldap_auth.Tls') as tls, \
                patch('app.auth.ldap_auth.Server'), \
                patch('app.auth.ldap_auth.Connection'):
            authenticate_ldap('ivanov', 'pw', app)

        tls.assert_called_once()
        assert tls.call_args.kwargs['validate'] == ssl.CERT_REQUIRED

    def test_internal_ca_file_is_passed_through(self, app):
        _configure(app, LDAP_CA_CERT_FILE='/etc/pass-manager/internal-ca.pem')

        with patch('app.auth.ldap_auth.Tls') as tls, \
                patch('app.auth.ldap_auth.Server'), \
                patch('app.auth.ldap_auth.Connection'):
            authenticate_ldap('ivanov', 'pw', app)

        assert tls.call_args.kwargs['ca_certs_file'] == '/etc/pass-manager/internal-ca.pem'

    def test_empty_ca_file_falls_back_to_system_store(self, app):
        """Пустая строка должна стать None, иначе ldap3 будет искать файл ''."""
        _configure(app, LDAP_CA_CERT_FILE='')

        with patch('app.auth.ldap_auth.Tls') as tls, \
                patch('app.auth.ldap_auth.Server'), \
                patch('app.auth.ldap_auth.Connection'):
            authenticate_ldap('ivanov', 'pw', app)

        assert tls.call_args.kwargs['ca_certs_file'] is None

    def test_tls_ciphers_passed_through(self, app):
        """Непустой LDAP_TLS_CIPHERS должен дойти до Tls как есть —
        именно по этой строке OpenSSL понижает seclevel для слабой PKI."""
        _configure(app, LDAP_TLS_CIPHERS='DEFAULT@SECLEVEL=1')

        with patch('app.auth.ldap_auth.Tls') as tls, \
                patch('app.auth.ldap_auth.Server'), \
                patch('app.auth.ldap_auth.Connection'):
            authenticate_ldap('ivanov', 'pw', app)

        assert tls.call_args.kwargs['ciphers'] == 'DEFAULT@SECLEVEL=1'

    def test_empty_tls_ciphers_becomes_none(self, app):
        """Пустая строка должна стать None, иначе OpenSSL получит мусорный
        пустой список шифров вместо системных умолчаний."""
        _configure(app, LDAP_TLS_CIPHERS='')

        with patch('app.auth.ldap_auth.Tls') as tls, \
                patch('app.auth.ldap_auth.Server'), \
                patch('app.auth.ldap_auth.Connection'):
            authenticate_ldap('ivanov', 'pw', app)

        assert tls.call_args.kwargs['ciphers'] is None

    def test_tls_ciphers_does_not_disable_validation(self, app):
        """Главный инвариант: понижение seclevel ≠ отключение проверки.
        При заданном LDAP_TLS_CIPHERS в Tls всё ещё уходит CERT_REQUIRED —
        цепочка проверяется, просто по более мягкому уровню."""
        _configure(app, LDAP_TLS_CIPHERS='DEFAULT@SECLEVEL=1')

        with patch('app.auth.ldap_auth.Tls') as tls, \
                patch('app.auth.ldap_auth.Server'), \
                patch('app.auth.ldap_auth.Connection'):
            authenticate_ldap('ivanov', 'pw', app)

        assert tls.call_args.kwargs['validate'] == ssl.CERT_REQUIRED


class TestPlaintextIsLoud:
    """Работа без SSL допустима технически, но должна быть заметна в логах."""

    def test_warns_when_ssl_disabled(self, app, caplog):
        _configure(app, LDAP_USE_SSL=False, LDAP_PORT=389)

        with patch('app.auth.ldap_auth.Server'), patch('app.auth.ldap_auth.Connection'):
            authenticate_ldap('ivanov', 'pw', app)

        assert 'открытым текстом' in caplog.text

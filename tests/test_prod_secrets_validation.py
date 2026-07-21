"""Тесты prod-secrets validation (B1/F-005, B8/F-013, B9/F-014).

Цель: убедиться, что gating в `_validate_prod_secrets` срабатывает
корректно для всех сценариев и что единственный легитимный bypass —
это TESTING=True (а НЕ DEBUG, как раньше).

Внимание: мы НЕ вызываем create_app('production') напрямую, т.к. она сама
запускает _validate_prod_secrets и упадёт на слабом SECRET_KEY из .env.
Вместо этого строим app через 'testing' (bypass на этапе create_app),
затем переопределяем config и вызываем _validate_prod_secrets явно.
"""
from __future__ import annotations

import pytest

from app import create_app, _validate_prod_secrets


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _make_app_for_validation(**overrides):
    """Создать app через 'testing' (чтобы обойти validation в create_app),
    затем переопределить config под конкретный сценарий проверки.

    Возвращает Flask app, готовый к передаче в _validate_prod_secrets.
    """
    app = create_app('testing')
    # Базовые безопасные значения, чтобы каждый тест переопределял только то,
    # что проверяет.
    from cryptography.fernet import Fernet
    app.config.update(
        TESTING=False,
        DEBUG=False,
        SECRET_KEY='a' * 64,
        ENCRYPTION_KEY=Fernet.generate_key().decode(),
        SESSION_COOKIE_SECURE=True,
    )
    if overrides:
        app.config.update(**overrides)
    return app


# --------------------------------------------------------------------------- #
# Bypass behavior
# --------------------------------------------------------------------------- #

class TestProdSecretsBypass:
    """Единственный bypass для prod-secrets — TESTING=True, не DEBUG."""

    def test_testing_true_bypasses_all_checks(self):
        """TESTING=True + DEBUG=False + плохие секреты → НЕ падает."""
        app = create_app('testing')
        # TestingConfig имеет TESTING=True и слабые секреты — должно пройти
        _validate_prod_secrets(app)

    def test_debug_true_does_not_bypass_secret_key(self):
        """DEBUG=True + TESTING=False + слабый SECRET_KEY → RuntimeError.

        Это ключевая регрессия F-014: раньше DEBUG освобождал от всех
        проверок, теперь — нет.
        """
        app = _make_app_for_validation(
            DEBUG=True,
            TESTING=False,
            SECRET_KEY='change-me',       # placeholder
            ENCRYPTION_KEY='',            # пустой (проверяем SECRET_KEY раньше)
        )
        with pytest.raises(RuntimeError, match='SECRET_KEY'):
            _validate_prod_secrets(app)

    def test_debug_true_does_not_bypass_encryption_key(self):
        """DEBUG=True + TESTING=False + сильный SECRET_KEY + нет ENCRYPTION_KEY → RuntimeError."""
        app = _make_app_for_validation(
            DEBUG=True,
            TESTING=False,
            SECRET_KEY='a' * 64,          # валидный
            ENCRYPTION_KEY='',            # no-op режим
        )
        with pytest.raises(RuntimeError, match='ENCRYPTION_KEY'):
            _validate_prod_secrets(app)

    def test_debug_true_bypasses_session_cookie_secure(self):
        """DEBUG=True → SESSION_COOKIE_SECURE может быть False (localhost HTTP).

        Это единственная проверка, от которой DEBUG всё ещё освобождает —
        чтобы локальная разработка по HTTP работала.
        """
        from cryptography.fernet import Fernet
        app = _make_app_for_validation(
            DEBUG=True,
            TESTING=False,
            SECRET_KEY='a' * 64,
            ENCRYPTION_KEY=Fernet.generate_key().decode(),
            SESSION_COOKIE_SECURE=False,   # допустимо в DEBUG
        )
        # Не должно упасть — DEBUG освобождает только от SESSION_COOKIE_SECURE
        _validate_prod_secrets(app)


# --------------------------------------------------------------------------- #
# SECRET_KEY checks (B1/F-005)
# --------------------------------------------------------------------------- #

class TestSecretKeyValidation:

    def test_placeholder_secret_key_raises(self):
        app = _make_app_for_validation(
            SECRET_KEY='change-me-to-random-64-char-hex-string',
        )
        with pytest.raises(RuntimeError, match='SECRET_KEY'):
            _validate_prod_secrets(app)

    def test_short_secret_key_raises(self):
        app = _make_app_for_validation(SECRET_KEY='short')  # < 32 символов
        with pytest.raises(RuntimeError, match='SECRET_KEY'):
            _validate_prod_secrets(app)

    def test_empty_secret_key_raises(self):
        app = _make_app_for_validation(SECRET_KEY='')
        with pytest.raises(RuntimeError, match='SECRET_KEY'):
            _validate_prod_secrets(app)


# --------------------------------------------------------------------------- #
# ENCRYPTION_KEY checks (B8/F-013)
# --------------------------------------------------------------------------- #

class TestEncryptionKeyValidation:

    def test_missing_encryption_key_raises(self):
        app = _make_app_for_validation(ENCRYPTION_KEY='')
        with pytest.raises(RuntimeError, match='ENCRYPTION_KEY'):
            _validate_prod_secrets(app)

    def test_valid_encryption_key_passes(self):
        from cryptography.fernet import Fernet
        app = _make_app_for_validation(
            SECRET_KEY='a' * 64,
            ENCRYPTION_KEY=Fernet.generate_key().decode(),
            SESSION_COOKIE_SECURE=True,
        )
        # Не должно упасть
        _validate_prod_secrets(app)


# --------------------------------------------------------------------------- #
# SESSION_COOKIE_SECURE checks (B9/F-014)
# --------------------------------------------------------------------------- #

class TestSessionCookieSecureValidation:

    def test_production_requires_session_cookie_secure(self):
        """В non-debug SESSION_COOKIE_SECURE=False → RuntimeError."""
        app = _make_app_for_validation(
            DEBUG=False,
            SESSION_COOKIE_SECURE=False,  # нарушение
        )
        with pytest.raises(RuntimeError, match='SESSION_COOKIE_SECURE'):
            _validate_prod_secrets(app)

    def test_production_ok_with_session_cookie_secure(self):
        """В non-debug с SESSION_COOKIE_SECURE=True → не падает."""
        app = _make_app_for_validation(
            DEBUG=False,
            SESSION_COOKIE_SECURE=True,
        )
        _validate_prod_secrets(app)


# --------------------------------------------------------------------------- #
# Runtime sanity: DevConfig без ENCRYPTION_KEY падает (главный сценарий F-014)
# --------------------------------------------------------------------------- #

class TestDevConfigF014Regression:
    """F-014: прод на DevConfig с plaintext-паролями должен падать на create_app."""

    def test_dev_config_without_encryption_key_raises(self):
        """DevConfig-семантика (DEBUG=True) с валидным SECRET_KEY, но пустым
        ENCRYPTION_KEY → RuntimeError.

        Главный regression-сценарий F-014: раньше DEBUG освобождал от всех
        проверок, теперь — нет. ENCRYPTION_KEY обязателен и для dev.

        Здесь мы моделируем DevConfig через прямой вызов _validate_prod_secrets
        (а не create_app), чтобы не зависеть от значения SECRET_KEY в .env.
        """
        app = _make_app_for_validation(
            DEBUG=True,
            TESTING=False,
            SECRET_KEY='a' * 64,      # валидный
            ENCRYPTION_KEY='',         # пустой → no-op режим
            SESSION_COOKIE_SECURE=False,
        )
        with pytest.raises(RuntimeError, match='ENCRYPTION_KEY'):
            _validate_prod_secrets(app)

    def test_testing_config_always_passes(self):
        """create_app('testing') не падает независимо от секретов."""
        app = create_app('testing')
        assert app.config.get('TESTING') is True

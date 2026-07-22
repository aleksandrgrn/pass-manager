from flask_login import UserMixin
from sqlalchemy.ext.hybrid import hybrid_property
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db
from app.security import decrypt, encrypt


class User(UserMixin, db.Model):
    """User model for authentication."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(256), nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)  # NULL for LDAP users
    role = db.Column(db.String(32), nullable=False, default='admin')
    is_local = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    @property
    def is_admin(self):
        return self.role in ('admin', 'superadmin')

    @property
    def is_superadmin(self):
        return self.role == 'superadmin'

    @property
    def can_view_passwords(self):
        return self.role == 'superadmin'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if self.password_hash is None:
            return False
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class Server(db.Model):
    """Server (VPS) model."""
    __tablename__ = 'servers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False, index=True)

    # Зашифрованные Fernet-секреты. Реальные колонки хранят токены,
    # публичные hybrid-свойства ниже прозрачно шифруют/расшифровывают.
    password_encrypted = db.Column('password_encrypted', db.Text, nullable=True)
    provider_password_encrypted = db.Column('provider_password_encrypted', db.Text, nullable=True)
    web_pass_encrypted = db.Column('web_pass_encrypted', db.Text, nullable=True)
    mgt_pass_encrypted = db.Column('mgt_pass_encrypted', db.Text, nullable=True)
    password_pending_encrypted = db.Column(db.Text, nullable=True)

    ip_address = db.Column(db.String(45), nullable=True, index=True)
    ssh_username = db.Column(db.String(64), nullable=False, default='root')
    provider = db.Column(db.String(256), nullable=True)
    provider_login = db.Column(db.String(256), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    os = db.Column(db.String(128), nullable=True)
    cpu = db.Column(db.String(128), nullable=True)
    ram = db.Column(db.String(64), nullable=True)
    # Services
    has_exim = db.Column(db.Boolean, default=False, nullable=False)
    has_squid = db.Column(db.Boolean, default=False, nullable=False)
    has_vpn = db.Column(db.Boolean, default=False, nullable=False)
    # VPS management panel
    website = db.Column(db.String(512), nullable=True)
    web_login = db.Column(db.String(256), nullable=True)
    vps_management_url = db.Column(db.String(512), nullable=True)
    mgt_login = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    domains = db.relationship('Domain', backref='server', lazy='dynamic', cascade='all, delete-orphan')

    # --- Hybrid properties: прозрачное шифрование паролей ---

    @hybrid_property
    def password(self):
        """Root-пароль сервера (расшифровывается при чтении)."""
        return decrypt(self.password_encrypted) if self.password_encrypted else None

    @password.setter
    def password(self, value):
        self.password_encrypted = encrypt(value) if value else None

    @hybrid_property
    def provider_password(self):
        """Пароль провайдера."""
        return decrypt(self.provider_password_encrypted) if self.provider_password_encrypted else None

    @provider_password.setter
    def provider_password(self, value):
        self.provider_password_encrypted = encrypt(value) if value else None

    @hybrid_property
    def web_pass(self):
        """Пароль панели управления VPS."""
        return decrypt(self.web_pass_encrypted) if self.web_pass_encrypted else None

    @web_pass.setter
    def web_pass(self, value):
        self.web_pass_encrypted = encrypt(value) if value else None

    @hybrid_property
    def mgt_pass(self):
        """Management-пароль."""
        return decrypt(self.mgt_pass_encrypted) if self.mgt_pass_encrypted else None

    @mgt_pass.setter
    def mgt_pass(self, value):
        self.mgt_pass_encrypted = encrypt(value) if value else None

    @hybrid_property
    def password_pending(self):
        return decrypt(self.password_pending_encrypted)

    @password_pending.setter
    def password_pending(self, value):
        self.password_pending_encrypted = encrypt(value)

    # --- Служебные свойства ---

    @property
    def services_list(self):
        services = []
        if self.has_exim:
            services.append('exim')
        if self.has_squid:
            services.append('squid')
        if self.has_vpn:
            services.append('vpn')
        return services

    def __repr__(self):
        return f'<Server {self.name} ({self.ip_address})>'


class Domain(db.Model):
    """Domain model linked to a server."""
    __tablename__ = 'domains'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(256), nullable=False, index=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False, index=True)

    def __repr__(self):
        return f'<Domain {self.domain}>'


class ServiceTemplate(db.Model):
    """Каталог Ansible-playbook'ов. Auto-discovered. A4 наполнит содержимое."""
    __tablename__ = 'service_templates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True, index=True)
    display_name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    playbook_path = db.Column(db.String(512), nullable=True)  # FIX-7: nullable
    discovered_at = db.Column(db.DateTime, server_default=db.func.now())
    last_seen_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def __repr__(self):
        return f'<ServiceTemplate {self.name}>'


class ServerService(db.Model):
    """M2M Server ↔ ServiceTemplate со status. A4 наполнит Ansible-логику."""
    __tablename__ = 'server_services'
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False, index=True)
    service_id = db.Column(db.Integer, db.ForeignKey('service_templates.id'), nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default='unknown')  # installed/unknown/failed
    last_checked_at = db.Column(db.DateTime, nullable=True)
    last_converge_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (
        db.UniqueConstraint('server_id', 'service_id', name='uq_server_service'),
    )

    def __repr__(self):
        return f'<ServerService server={self.server_id} service={self.service_id} status={self.status}>'


class ProvisioningJob(db.Model):
    """История запусков pipeline. A3 наполнит steps_json и async-логику."""
    __tablename__ = 'provisioning_jobs'
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=True, index=True)  # nullable for batch jobs (A5)
    initiated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    job_type = db.Column(db.String(32), nullable=False)  # onboarding/service_install/service_probe/root_rotate
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending/running/success/failed/cancelled
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    steps_json = db.Column(db.Text, nullable=True)  # JSON-лог шагов
    error_message = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<ProvisioningJob {self.job_type} server={self.server_id} status={self.status}>'


class AccessAssignment(db.Model):
    """Policy decision: какому пользователю выдан доступ к серверу.
    Логика grant/revoke/batch-revoke — в A5. Здесь только schema.
    Note: partial unique index on (server_id, user_id) WHERE state='active'
    не добавлен здесь (SQLite-specific concern) — будет в A5 вместе с логикой.
    Пока это plain history table."""
    __tablename__ = 'access_assignments'
    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    state = db.Column(db.String(16), nullable=False, default='active', index=True)  # active/revoked
    granted_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    granted_at = db.Column(db.DateTime, server_default=db.func.now())
    revoked_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    vps_manager_key_id = db.Column(db.Integer, nullable=True)  # ссылка на ключ в VPS Manager

    def __repr__(self):
        return f'<AccessAssignment server={self.server_id} user={self.user_id} state={self.state}>'

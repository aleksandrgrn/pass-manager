"""Server-related forms."""
from flask_wtf import FlaskForm
from wtforms import (
    StringField, TextAreaField, BooleanField, HiddenField, FieldList, IntegerField
)
from wtforms.validators import DataRequired, Optional, NumberRange


class ServerForm(FlaskForm):
    """Form for creating/editing a server (full record)."""
    name = StringField('Название', validators=[DataRequired(message='Название обязательно')])
    password = StringField('Пароль', validators=[Optional()])
    ip_address = StringField('IP-адрес', validators=[Optional()])
    provider = StringField('Провайдер', validators=[Optional()])
    provider_login = StringField('Логин провайдера', validators=[Optional()])
    provider_password = StringField('Пароль провайдера', validators=[Optional()])
    notes = TextAreaField('Комментарии', validators=[Optional()])
    active = BooleanField('Активен', default=True)
    os = StringField('ОС', validators=[Optional()])
    cpu = StringField('CPU', validators=[Optional()])
    ram = StringField('RAM', validators=[Optional()])
    # Services
    has_exim = BooleanField('Exim', default=False)
    has_squid = BooleanField('Squid', default=False)
    has_vpn = BooleanField('VPN', default=False)
    # VPS management
    website = StringField('Website', validators=[Optional()])
    web_login = StringField('Web Login', validators=[Optional()])
    web_pass = StringField('Web Password', validators=[Optional()])
    vps_management_url = StringField('VPS Management URL', validators=[Optional()])
    mgt_login = StringField('Management Login', validators=[Optional()])
    mgt_pass = StringField('Management Password', validators=[Optional()])
    # Track C A3: онбординг pipeline (specs/track-c-plan-A3.md, Фаза A3.1)
    ssh_username = StringField('Bootstrap-пользователь', default='root', validators=[Optional()])  # FIX-9: пишется в модель
    ssh_port = IntegerField('SSH-порт', default=22,
                            validators=[Optional(), NumberRange(min=1, max=65535)])
    do_onboarding = BooleanField('Выполнить автоматический онбординг', default=False)  # транзиентное
    bootstrap_password = StringField('Пароль для bootstrap', validators=[Optional()])  # транзиентное (FIX-5), в БД не хранится


class ServerFilterForm(FlaskForm):
    """Form for filtering the servers list."""
    q = StringField('Поиск', validators=[Optional()])
    active = BooleanField('Только активные', default=False)


# Whitelist of fields allowed for inline HTMX editing.
# Maps incoming field name → model attribute.
INLINE_EDITABLE_FIELDS = {
    'name': 'name',
    'password': 'password',
    'ip_address': 'ip_address',
    'provider': 'provider',
    'provider_login': 'provider_login',
    'provider_password': 'provider_password',
    'notes': 'notes',
    'os': 'os',
    'cpu': 'cpu',
    'ram': 'ram',
    'website': 'website',
    'web_login': 'web_login',
    'web_pass': 'web_pass',
    'vps_management_url': 'vps_management_url',
    'mgt_login': 'mgt_login',
    'mgt_pass': 'mgt_pass',
}

# Boolean toggle fields. Сервисы (has_exim/has_squid/has_vpn) убраны из
# inline-toggle в A1 — в A4 будут управляться через карточку сервера.
INLINE_TOGGLE_FIELDS = {'active': 'active'}

# Транзиентные поля ServerForm (Track C A3): в модель не пишутся, populate_obj
# должен их исключить (см. views.py::create()).
TRANSIENT_FORM_FIELDS = ('do_onboarding', 'bootstrap_password')

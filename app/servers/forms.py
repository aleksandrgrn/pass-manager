"""Server-related forms."""
from flask_wtf import FlaskForm
from wtforms import (
    StringField, TextAreaField, BooleanField, HiddenField, FieldList, IntegerField,
    SelectField
)
from wtforms.validators import DataRequired, Optional, NumberRange, ValidationError


class ServerForm(FlaskForm):
    """Form for creating/editing a server (full record)."""

    # Ставится в create(): при заведении «Пароль root» — это текущий пароль от
    # хостера, вход онбординга, и без него bootstrap заведомо упадёт. В форме
    # правки флаг остаётся False: пароль там уже есть, а у части импортированных
    # записей его исторически нет — обязательность заблокировала бы сохранение.
    require_password = False
    name = StringField('Название', validators=[DataRequired(message='Название обязательно')])
    # Track C B1: без группы сервер видит только суперадмин, поэтому админ,
    # заведя сервер, тут же терял бы его из виду. Варианты подставляет view —
    # список зависит от того, кто именно заполняет форму.
    group_id = SelectField('Группа', coerce=int, validators=[Optional()])
    # Без Optional(): он на пустом поле рвёт цепочку через StopValidation, и
    # validate_password ниже не запускается вовсе. Обязательным поле делает
    # только require_password.
    password = StringField('Пароль root')  # FIX-FORM-PW: прежнее «Пароль» путали с bootstrap_password
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
    ssh_username = StringField('SSH-пользователь', default='root', validators=[Optional()])  # FIX-9: пишется в модель; FIX-FORM-PW: к бутстрапу отношения не имеет
    ssh_port = IntegerField('SSH-порт', default=22,
                            validators=[Optional(), NumberRange(min=1, max=65535)])

    def validate_password(self, field):
        """Пустой пароль при заведении создаёт job, который уже не починить.

        Пароль лежит в `steps_json` и стирается только после успеха, поэтому
        «Перезапустить шаг» на карточке вечно повторял бы попытку с пустым
        значением, а ввести пароль задним числом негде.
        """
        if self.require_password and not (field.data or '').strip():
            raise ValidationError(
                'Введите текущий пароль root от хостера — '
                'без него автоматический онбординг не выполнится',
            )


class ServerFilterForm(FlaskForm):
    """Фильтры списка серверов.

    Галка именно «показывать неактивные», а не «только активные»: снятый
    чекбокс браузер не отправляет вовсе, и «первый заход» неотличим от
    «человек снял галку». При такой формулировке оба случая означают одно и
    то же и означают нужное — прятать неактуальные. Обратная формулировка
    потребовала бы скрытого поля-маркера, иначе галку нельзя было бы снять.
    """
    q = StringField('Поиск', validators=[Optional()])
    show_inactive = BooleanField('Показывать неактивные')


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

# Пароль root — единственный секрет, закрытый от админа: это доступ к самой
# машине. Учётки провайдера и панелей видит и правит тот, кто видит сервер.
# Единый список для формы, inline-правки и шаблонов: граница должна быть одна,
# иначе поле, скрытое в списке, вылезает в форме (так и случилось).
PASSWORD_FORM_FIELDS = ('password',)

# Boolean toggle fields. Сервисы (has_exim/has_squid/has_vpn) убраны из
# inline-toggle в A1 — в A4 будут управляться через карточку сервера.
INLINE_TOGGLE_FIELDS = {'active': 'active'}

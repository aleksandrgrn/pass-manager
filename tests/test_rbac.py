"""Тесты RBAC: видимость столбцов и значений паролей по ролям."""
from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# Видимость столбца "Пароль" в /servers/
# --------------------------------------------------------------------------- #

class TestPasswordColumnVisibility:
    """Столбец 'Пароль' должен присутствовать только для superadmin."""

    def test_admin_does_not_see_password_column(self, admin_client, sample_server):
        """admin не должен видеть столбец 'Пароль' в шапке таблицы."""
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert '<th>Пароль</th>' not in body

    def test_superadmin_sees_password_column(self, superadmin_client, sample_server):
        """superadmin видит столбец 'Пароль'."""
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert '<th>Пароль</th>' in body


# --------------------------------------------------------------------------- #
# Видимость значения пароля в HTML
# --------------------------------------------------------------------------- #

class TestPasswordValueVisibility:
    """Значение пароля сервера должно присутствовать в HTML только для superadmin."""

    def test_admin_does_not_see_password_value(self, admin_client, sample_server):
        """admin не должен видеть сам пароль в HTML списка."""
        body = admin_client.get('/servers/').get_data(as_text=True)
        assert 's3cret-root-pass' not in body

    def test_superadmin_sees_password_value(self, superadmin_client, sample_server):
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert 's3cret-root-pass' in body


# --------------------------------------------------------------------------- #
# Детальная страница
# --------------------------------------------------------------------------- #

class TestDetailPage:
    """GET /servers/<id> — видимость пароля по ролям."""

    def test_admin_detail_has_no_password(self, admin_client, sample_server):
        resp = admin_client.get(f'/servers/{sample_server.id}')
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 's3cret-root-pass' not in body
        # Должна быть индикация скрытия паролей
        assert 'Пароль root скрыт' in body

    def test_superadmin_detail_has_password(self, superadmin_client, sample_server):
        body = superadmin_client.get(f'/servers/{sample_server.id}').get_data(as_text=True)
        assert 's3cret-root-pass' in body


# --------------------------------------------------------------------------- #
# inline edit endpoint — RBAC enforcement (FIX-6b: metadata vs password split)
# --------------------------------------------------------------------------- #

class TestEditFieldSplit:
    """FIX-6b: metadata доступна admin+, password-поля — только superadmin."""

    def test_admin_can_edit_metadata_field(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'name', 'value': 'renamed-by-admin'},
        )
        assert resp.status_code == 200

    def test_admin_cannot_edit_password_field(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'HACKED'},
        )
        assert resp.status_code == 403

    def test_superadmin_can_edit_password_field(self, superadmin_client, sample_server):
        resp = superadmin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'new-pass-456'},
        )
        assert resp.status_code == 200


class TestInlineEditRbac:
    """POST /servers/<id>/field — admin: metadata OK / password 403; superadmin: всё OK."""

    def test_admin_cannot_edit_password_field(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'HACKED'},
        )
        assert resp.status_code == 403

    @pytest.mark.parametrize('field,value', [
        ('name', 'renamed-by-admin'),
        ('ip_address', '203.0.113.10'),
        ('notes', 'changed'),
    ])
    def test_admin_can_edit_non_password_fields(
        self, admin_client, sample_server, field, value,
    ):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': field, 'value': value},
        )
        assert resp.status_code == 200

    def test_superadmin_can_edit_password_field(self, superadmin_client, sample_server):
        """superadmin может редактировать пароль → 200 и значение меняется в БД."""
        from app.models import Server
        resp = superadmin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'new-pass-456'},
        )
        assert resp.status_code == 200
        # Проверяем, что значение реально записано (через гибридное свойство).
        from app.extensions import db
        with db.session.no_autoflush:
            refreshed = db.session.get(Server, sample_server.id)
            assert refreshed.password == 'new-pass-456'


# --------------------------------------------------------------------------- #
# Mutating endpoints: обе роли (admin + superadmin) могут мутировать серверы
# --------------------------------------------------------------------------- #

class TestRbacOnMutatingEndpoints:
    """После A1: admin и superadmin могут все mutating-действия над серверами."""

    def test_anon_cannot_create_server(self, client):
        resp = client.post('/servers/new', data={
            'name': 'evil', 'ip_address': '203.0.113.99',
        })
        assert resp.status_code in (302, 401)

    def test_anon_cannot_edit_server(self, client, sample_server):
        resp = client.post(f'/servers/{sample_server.id}/edit', data={
            'name': 'hacked', 'ip_address': sample_server.ip_address,
        })
        assert resp.status_code in (302, 401)

    def test_anon_cannot_delete_server(self, client, sample_server):
        resp = client.post(f'/servers/{sample_server.id}/delete')
        assert resp.status_code in (302, 401)

    def test_anon_cannot_toggle_field(self, client, sample_server):
        resp = client.post(
            f'/servers/{sample_server.id}/toggle',
            data={'field': 'active'},
        )
        assert resp.status_code in (302, 401)

    def test_anon_cannot_add_domain(self, client, sample_server):
        resp = client.post(
            f'/servers/{sample_server.id}/domains',
            data={'domain': 'evil.com'},
        )
        assert resp.status_code in (302, 401)

    def test_anon_cannot_delete_domain(self, client, sample_server):
        from app.models import Domain
        domain = Domain.query.filter_by(server_id=sample_server.id).first()
        resp = client.post(f'/servers/domains/{domain.id}/delete')
        assert resp.status_code in (302, 401)

    def test_admin_can_create_server(self, admin_client):
        resp = admin_client.post('/servers/new', data={
            'name': 'new-prod-01', 'ip_address': '192.0.2.50',
            'password': 'Init-Pass-123!',
        })
        assert resp.status_code == 302

    def test_admin_can_edit_server(self, admin_client, sample_server):
        resp = admin_client.post(f'/servers/{sample_server.id}/edit', data={
            'name': sample_server.name, 'ip_address': '203.0.113.20',
        })
        assert resp.status_code == 302

    def test_admin_can_delete_server(self, admin_client, sample_server):
        resp = admin_client.post(f'/servers/{sample_server.id}/delete')
        assert resp.status_code == 302

    def test_admin_can_toggle_active(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/toggle',
            data={'field': 'active'},
        )
        assert resp.status_code == 200

    def test_admin_can_add_domain(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/domains',
            data={'domain': 'newdomain.com'},
        )
        assert resp.status_code == 200

    def test_admin_can_delete_domain(self, admin_client, sample_server):
        from app.models import Domain
        domain = Domain.query.filter_by(server_id=sample_server.id).first()
        resp = admin_client.post(f'/servers/domains/{domain.id}/delete')
        assert resp.status_code == 204

    def test_superadmin_can_create_server(self, superadmin_client):
        resp = superadmin_client.post('/servers/new', data={
            'name': 'new-prod-02', 'ip_address': '192.0.2.51',
            'password': 'Init-Pass-123!',
        })
        assert resp.status_code == 302

    def test_superadmin_can_delete_server(self, superadmin_client, sample_server):
        resp = superadmin_client.post(f'/servers/{sample_server.id}/delete')
        assert resp.status_code == 302


# --------------------------------------------------------------------------- #
# Role properties на модели User
# --------------------------------------------------------------------------- #

class TestRoleProperties:
    """User(role=...) → is_admin / is_superadmin / can_view_passwords."""

    def test_admin_role_properties(self, app):
        from app.models import User
        u = User(username='x', role='admin')
        assert u.is_admin is True
        assert u.is_superadmin is False
        assert u.can_view_passwords is False

    def test_superadmin_role_properties(self, app):
        from app.models import User
        u = User(username='y', role='superadmin')
        assert u.is_admin is True
        assert u.is_superadmin is True
        assert u.can_view_passwords is True

    def test_new_user_has_null_key_fields(self, app):
        from app.models import User
        u = User(username='z', role='admin')
        assert u.vps_manager_key_id is None
        assert u.key_downloaded_at is None


# --------------------------------------------------------------------------- #
# Форма редактирования — та же граница, что у списка и карточки
# --------------------------------------------------------------------------- #

class TestEditFormPasswords:
    """GET/POST /servers/<id>/edit: пароли — только суперадмину."""

    def test_admin_edit_form_has_no_passwords(self, admin_client, sample_server):
        body = admin_client.get(
            f'/servers/{sample_server.id}/edit'
        ).get_data(as_text=True)
        assert 's3cret-root-pass' not in body

    def test_superadmin_edit_form_has_passwords(self, superadmin_client, sample_server):
        body = superadmin_client.get(
            f'/servers/{sample_server.id}/edit'
        ).get_data(as_text=True)
        assert 's3cret-root-pass' in body

    def test_admin_edit_post_cannot_change_password(
        self, admin_client, sample_server, db,
    ):
        resp = admin_client.post(f'/servers/{sample_server.id}/edit', data={
            'name': 'vps-test-01', 'password': 'HACKED',
        })
        assert resp.status_code == 302
        db.session.refresh(sample_server)
        assert sample_server.password == 's3cret-root-pass'


# --------------------------------------------------------------------------- #
# Граница проходит по паролю root, а не по подстроке "pass" в имени поля
# --------------------------------------------------------------------------- #

class TestOnlyRootPasswordIsSecret:
    """Учётки провайдера и панелей видит и правит тот, кто видит сервер."""

    @pytest.mark.parametrize('url', ['/servers/', '/servers/{id}', '/servers/{id}/edit'])
    def test_admin_sees_provider_password(self, admin_client, sample_server, url):
        body = admin_client.get(
            url.format(id=sample_server.id)
        ).get_data(as_text=True)
        assert 'prov-pass-123' in body
        assert 's3cret-root-pass' not in body

    def test_admin_can_inline_edit_provider_password(self, admin_client, sample_server, db):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'provider_password', 'value': 'prov-new'},
        )
        assert resp.status_code == 200
        db.session.refresh(sample_server)
        assert sample_server.provider_password == 'prov-new'

    def test_admin_still_cannot_inline_edit_root_password(self, admin_client, sample_server):
        resp = admin_client.post(
            f'/servers/{sample_server.id}/field',
            data={'field': 'password', 'value': 'HACKED'},
        )
        assert resp.status_code == 403

    def test_admin_edit_post_can_change_provider_password(self, admin_client, sample_server, db):
        resp = admin_client.post(f'/servers/{sample_server.id}/edit', data={
            'name': 'vps-test-01', 'provider_password': 'prov-via-form',
            'password': 'HACKED',
        })
        assert resp.status_code == 302
        db.session.refresh(sample_server)
        assert sample_server.provider_password == 'prov-via-form'
        assert sample_server.password == 's3cret-root-pass'


# --------------------------------------------------------------------------- #
# Шторка на паролях в списке
# --------------------------------------------------------------------------- #

class TestPasswordMask:
    """Пароли доходят до страницы, но закрыты шторкой из точек.

    Проверяем присутствие правила, а не картинку: поведение (клик раскрывает
    на три секунды, Esc отменяет правку) живёт в браузере и проверяется руками.
    Здесь ловится единственный отказ, который тихо пройдёт мимо всех остальных
    тестов, — если правило маски удалят при следующей правке вёрстки и одна из
    колонок останется открытой.
    """

    # FIX-MASK-1: префикс table.tbl td перенесён внутрь :is(...), чтобы четвёртым
    # пунктом туда мог встать .pw-mask (карточка и форма не в таблице).
    # FIX-MASK-3: маска переехала с data-inline-edit на класс, список маскируемых
    # полей теперь живёт в шаблонах (_row.html, _cell.html, detail.html), а тут
    # осталось одно правило на все четыре места. Класс в селекторе продублирован:
    # одиночный дал бы 0-1-0 и проиграл бы утилите .text-xs из Tailwind CDN,
    # который дописывает свой <style> после нашего блока (наш — седьмой элемент
    # head, тейлвиндовский — тринадцатый). Дубль даёт 0-2-0 и бьёт любую
    # одиночную утилиту независимо от порядка.
    MASK = '.pw-mask.pw-mask'

    def test_mask_covers_both_password_columns(self, superadmin_client, sample_server):
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert self.MASK in body, 'селектор шторки пропал из base.html'
        # Селектор с .pw-mask обязан стоять во всех четырёх правилах шторки:
        # выпавшее из одного правила поле останется открытым (например, если
        # .pw-mask убрать только из font-size:0, текст в карточке не схлопнется).
        assert body.count(self.MASK) == 4, 'шторка маскирует не все списки полей'
        assert 'font-size: 0;' in body, 'шторка не схлопывает настоящий текст'
        assert "content: '••••••••'" in body, 'точки не рисуются'

    def test_mask_lifts_for_revealed_and_edited_cells(self, superadmin_client, sample_server):
        """Без этих исключений ячейку нельзя ни прочитать, ни отредактировать:
        точки остались бы висеть поверх поля ввода."""
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert f'{self.MASK}:is(.revealed, [data-editing="1"])' in body

    def test_password_value_still_reachable_for_copying(self, superadmin_client, sample_server):
        """Шторка прячет от глаз, а не удаляет: копирование по клику берёт
        значение из разметки, и оно обязано там остаться."""
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert 's3cret-root-pass' in body

    def test_filled_list_cells_carry_mask(self, superadmin_client, sample_server):
        """FIX-MASK-3: заполненный сервер — обе парольные ячейки несут pw-mask.

        Проверяем именно полную строку class, а не голую подстроку 'pw-mask':
        она живёт и в CSS base.html (селектор шторки) и в JS-обработчике клика.
        """
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert 'class="cursor-text font-mono text-xs pw-mask"' in body, \
            'root-ячейка списка не под шторкой'
        assert 'class="cursor-text pw-mask"' in body, \
            'ячейка пароля провайдера не под шторкой'

    def test_empty_list_cells_show_dash_without_mask(self, superadmin_client, db):
        """FIX-MASK-3: сервер без паролей не должен выглядеть заполненным.

        Ни одна парольная ячейка не несёт pw-mask, в ячейках прочерк, а
        data-inline-edit и data-server-id остаются на месте — на них держатся
        редактор и копирование по клику.
        """
        from app.models import Server
        bare = Server(name='bare-list-server')
        db.session.add(bare)
        db.session.commit()
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        root_cell = (
            f'data-inline-edit="password" data-server-id="{bare.id}" '
            'class="cursor-text font-mono text-xs">'
        )
        assert root_cell in body, 'root-ячейка потеряла data-inline-edit'
        assert f'{root_cell}\n            —' in body, \
            'root-ячейка без пароля показывает не прочерк'
        provider_cell = (
            f'data-inline-edit="provider_password" data-server-id="{bare.id}" '
            'class="cursor-text">'
        )
        assert provider_cell in body, 'ячейка провайдера потеряла data-inline-edit'
        assert f'{provider_cell}—</div>' in body, \
            'ячейка провайдера без пароля показывает не прочерк'

    def test_duplicated_class_guard(self, superadmin_client, sample_server):
        """Дубль класса охраняется явно.

        Одиночный класс (0-1-0) проиграл бы .text-xs из Tailwind CDN, который
        дописывает свой <style> после нашего блока. Строковая проверка
        специфичность не доказывает, но ловит «уборку» дубля при следующей
        правке вёрстки — она проскочила бы мимо всех остальных тестов.
        """
        body = superadmin_client.get('/servers/').get_data(as_text=True)
        assert '.pw-mask.pw-mask' in body, 'дубль класса убран из селектора шторки'


# --------------------------------------------------------------------------- #
# Шторка после инлайн-правки (FIX-MASK-3)
# --------------------------------------------------------------------------- #

class TestListMaskAfterInlineEdit:
    """POST /servers/<id>/field возвращает _cell.html — он обязан сам вешать
    pw-mask, иначе маска слетит после каждой правки пароля до перезагрузки."""

    URL = '/servers/{id}/field'

    @pytest.mark.parametrize('field,value', [
        ('password', 'new-pass-456'),
        ('provider_password', 'prov-new-789'),
    ])
    def test_nonempty_password_edit_returns_masked_cell(
        self, superadmin_client, sample_server, field, value,
    ):
        resp = superadmin_client.post(
            self.URL.format(id=sample_server.id),
            data={'field': field, 'value': value},
        )
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        prefix = 'cursor-text font-mono text-xs' if field == 'password' else 'cursor-text'
        assert f'class="{prefix} pw-mask"' in body, \
            f'ячейка {field} после правки вернулась без шторки'
        assert value in body

    def test_empty_password_edit_returns_dash_without_mask(
        self, superadmin_client, sample_server,
    ):
        """Правка, стирающая пароль, обязана вернуть прочерк, а не точки:
        у пустой ячейки нет значения, прятать нечего."""
        resp = superadmin_client.post(
            self.URL.format(id=sample_server.id),
            data={'field': 'password', 'value': ''},
        )
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'class="cursor-text font-mono text-xs pw-mask"' not in body
        assert '—' in body


# --------------------------------------------------------------------------- #
# Шторка на паролях в карточке и в форме правки (FIX-MASK-1)
# --------------------------------------------------------------------------- #

class TestCardMask:
    """Карточка /servers/<id>: пароли закрыты шторкой, но остаются в разметке."""

    DETAIL_URL = '/servers/{id}'

    def test_four_passwords_masked_on_detail(self, superadmin_client, sample_server, db):
        """Все четыре поля карточки под шторкой, каждое отдельно.

        Считаем именно вложенный класс у значений, а не однократное
        присутствие на странице: `.pw-mask` есть и в CSS карточки, и у всех
        четырёх <dd>, так что одиночный поиск ничего бы не поймал.

        FIX-MASK-2: шторка стала условной, поэтому сервер должен иметь пароли
        во всех четырёх полях. У образца из фикстуры заполнены только
        password и provider_password, а mgt_pass/web_pass пусты — без правки
        ниже они показали бы прочерк без точек, и граница «есть значение →
        точки» проверялась бы только на двух полях.
        """
        sample_server.web_pass = 'web-pass-1'
        sample_server.mgt_pass = 'mgt-pass-1'
        db.session.commit()
        body = superadmin_client.get(
            self.DETAIL_URL.format(id=sample_server.id)
        ).get_data(as_text=True)
        assert body.count('class="inline font-mono pw-mask"') == 4

    def test_root_password_not_leaked_to_admin_on_detail(self, admin_client, sample_server):
        """Шторка и права — разные вещи: админ видит пароль провайдера, но
        root-пароль в страницу не попадает вовсе (см. TestOnlyRootPasswordIsSecret)."""
        body = admin_client.get(self.DETAIL_URL.format(id=sample_server.id)).get_data(as_text=True)
        assert 'prov-pass-123' in body
        assert 's3cret-root-pass' not in body

    def test_empty_server_shows_dash_not_masks(self, superadmin_client, db):
        """FIX-MASK-2: сервер без паролей не должен выглядеть заполненным.

        Точки рисуются только там, где есть что прятать: у пустых полей нет
        класса pw-mask, и они показывают прочерк, как все остальные пустые
        поля карточки. Проверяем именно строку класса у <dd>, а не голую
        подстроку 'pw-mask': она живёт и в инлайн-CSS base.html (селектор
        шторки), так что буквальный поиск был бы красным всегда.
        """
        from app.models import Server
        bare = Server(name='bare-empty-server')
        db.session.add(bare)
        db.session.commit()
        body = superadmin_client.get(
            self.DETAIL_URL.format(id=bare.id)
        ).get_data(as_text=True)
        assert 'class="inline font-mono pw-mask"' not in body
        assert '—' in body

    def test_click_selector_guard(self, superadmin_client, sample_server):
        """Охрана селектора клика на карточке.

        Раскрытие по клику ловит поле через closest('[data-inline-edit],
        .pw-mask') — второй вариант нужен карточке, где у <dd> нет
        data-inline-edit, только класс. Удаление , .pw-mask из обработчика
        не роняет ни одного теста, но карточка при этом закрывается
        навсегда — эту строку держим в разметке явно.
        """
        body = superadmin_client.get(
            self.DETAIL_URL.format(id=sample_server.id)
        ).get_data(as_text=True)
        assert "closest('[data-inline-edit], .pw-mask')" in body


class TestEditFormMask:
    """Форма правки: все password-поля закрыты type="password".

    Нельзя переключать StringField на PasswordField в forms.py: она не отдаёт
    значение при перерисовке, и submit затрёт пароли пустотой. Ниже это
    зафиксировано и как наличие type="password", и как round-trip без потерь.
    """

    URL = '/servers/{id}/edit'

    def test_edit_fields_have_password_type(self, superadmin_client, sample_server):
        """На странице правки суперадмин видит четыре password-инпута.

        Второго поля пароля на странице больше нет — оно удалено вместе с галкой."""
        body = superadmin_client.get(
            self.URL.format(id=sample_server.id)
        ).get_data(as_text=True)
        for field in ('password', 'provider_password', 'web_pass', 'mgt_pass'):
            assert f'name="{field}" type="password"' in body, \
                f'{field} не закрыт шторкой в форме правки'

    def test_password_has_password_type_on_create(self, superadmin_client):
        """На странице создания «Пароль root» тоже закрыт шторкой: туда вводят
        текущий пароль от хостера."""
        body = superadmin_client.get('/servers/new').get_data(as_text=True)
        assert 'name="password" type="password"' in body

    def test_edit_roundtrips_passwords_without_clearing(self, superadmin_client, sample_server, db):
        """Главный тест: submit формы теми же значениями не трёт пароли.

        Сначала убеждаемся, что форма несёт расшифрованные значения в разметке
        (StringField отдаёт их в value, PasswordField отдал бы пустоту), затем
        повторяем submit ими же и сверяем с БД.
        """
        url = self.URL.format(id=sample_server.id)
        render = superadmin_client.get(url).get_data(as_text=True)
        assert 'value="s3cret-root-pass"' in render, \
            'форма не возвращает password в разметку (похоже на PasswordField)'
        assert 'value="prov-pass-123"' in render, \
            'форма не возвращает provider_password в разметку'

        resp = superadmin_client.post(url, data={
            'name': sample_server.name,
            'group_id': sample_server.group_id,
            'ip_address': sample_server.ip_address,
            'provider': sample_server.provider,
            'provider_login': sample_server.provider_login,
            'os': sample_server.os,
            'ssh_username': 'root',
            'ssh_port': '22',
            'password': 's3cret-root-pass',
            'provider_password': 'prov-pass-123',
        })
        assert resp.status_code == 302
        db.session.refresh(sample_server)
        assert sample_server.password == 's3cret-root-pass'
        assert sample_server.provider_password == 'prov-pass-123'

    def test_edit_saves_server_without_password(self, superadmin_client, db, default_group):
        """Пароль обязателен только при заведении — в форме правки нет.

        У части импортированных из MySQL записей root-пароля нет вовсе (в
        прогоне C1 по парку таких нашлось шесть). Стань validate_password
        безусловным — суперадмин перестал бы сохранять такие серверы, а
        остальной набор этого не заметил бы.
        """
        from app.models import Server
        server = Server(
            group_id=default_group.id,
            name='vps-no-pw-01',
            ip_address='192.0.2.99',
            active=True,
        )
        db.session.add(server)
        db.session.commit()

        resp = superadmin_client.post(self.URL.format(id=server.id), data={
            'name': 'vps-no-pw-01-renamed',
            'group_id': server.group_id,
            'ip_address': '192.0.2.99',
            'ssh_username': 'root',
            'ssh_port': '22',
        })
        assert resp.status_code == 302
        db.session.refresh(server)
        assert server.name == 'vps-no-pw-01-renamed'
        assert server.password is None

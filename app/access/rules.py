"""Единственное место, где решается «кому какие серверы видны».

Все серверные маршруты обращаются сюда, а не строят фильтры сами. Централизация не
украшательство: от неё зависит стоимость будущего делегирования прав руководителям
групп (Р7) — там меняется одно условие вместо восьми обработчиков.

Правило (specs/track-c-access-design.md, «Правило видимости»):
  superadmin — все серверы;
  admin      — серверы своих групп ∪ серверы с его активной точечной выдачей.

Смотрим именно на активные выдачи: на этом держится то, что отзыв сам собой убирает
сервер из списка, без отдельного механизма.
"""
from flask import abort
from flask_login import current_user
from sqlalchemy import or_

from app.models import AccessAssignment, Server


def _group_ids(user):
    """Идентификаторы групп, в которых состоит пользователь."""
    return [membership.group_id for membership in user.group_memberships]


def _granted_server_ids(user):
    """Подзапрос: серверы, где у пользователя активная точечная выдача."""
    return (
        AccessAssignment.query
        .with_entities(AccessAssignment.server_id)
        .filter(
            AccessAssignment.user_id == user.id,
            AccessAssignment.state == 'active',
        )
    )


def visible_servers(user):
    """Query серверов, доступных пользователю.

    Возвращает именно Query, а не список: поверх него в list_servers работают
    фильтры, сортировка по whitelist и paginate() — список их все сломает.
    """
    if user.is_superadmin:
        return Server.query

    return Server.query.filter(
        or_(
            Server.group_id.in_(_group_ids(user)),
            Server.id.in_(_granted_server_ids(user)),
        )
    )


def assert_can_access_server(server):
    """403, если текущий пользователь не должен видеть этот сервер.

    Namely 403, а не 404: так требует SC-R2.4 архитектуры. Сервер существует,
    просто он не твой — прятать сам факт существования мы не пытаемся.
    """
    if current_user.is_superadmin:
        return

    if server.group_id is not None and server.group_id in _group_ids(current_user):
        return

    has_grant = AccessAssignment.query.filter_by(
        user_id=current_user.id,
        server_id=server.id,
        state='active',
    ).first()
    if has_grant is not None:
        return

    abort(403, description='Сервер не входит в ваши группы')


def can_self_grant(user, server):
    """Может ли пользователь выдать себе доступ на этот сервер сам.

    Строже правила видимости: сервер должен входить в группу человека. Точечная
    выдача суперадмина кнопки не даёт — иначе отзыв ничего не значит: человек
    нажмёт кнопку и заведёт себе вторую активную выдачу, уже от своего имени.
    """
    return server.group_id is not None and server.group_id in _group_ids(user)

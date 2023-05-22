import logging
import uuid

from flask import Blueprint, jsonify, Response

from api.v1.msg_text import MsgText
from db.db import db
from models.db_models import User, Role, Permission, Require
from models.swagger_schema import PermissionShema, RequireShema

permission = Blueprint('permission', __name__)
log = logging.getLogger(__name__)


def get_perm_service(perm_id: uuid) -> PermissionShema:
    """Проверить доступы юзера"""
    permission = Permission.query.filter_by(id=perm_id).first()
    permissions_out = PermissionShema().dump(permission)
    return permissions_out


def add_perm_service(perm_name, role_name, description) -> Response:
    """Добавить доступы к роли"""
    role = Role.query.filter_by(name=role_name).first()
    perm = Permission(name=perm_name, description=description, role_id=role.id)
    db.session.add(perm)
    db.session.commit()
    return jsonify(permission=perm)


def change_perm_service(perm_id: uuid, description: str) -> RequireShema:
    """Изменить доступы юзера"""
    require = db.session.query(Require).get(perm_id)
    require.description = description
    db.session.add(require)
    db.session.commit()
    require_out = RequireShema().dump(require)
    return require_out


def get_perms_service(perm_id: uuid) -> [RequireShema]:
    """Получить все доступы юзера"""
    require = Require.query.filter_by(id=perm_id).all()
    require_out = RequireShema(many=True).dump(require)
    return require_out


def add_perms_service(perm_name: str, description: str) -> Response:
    """Создать новые настройки доступа"""
    required = Require(name=perm_name, description=description)
    db.session.add(required)
    db.session.commit()
    return jsonify(required=required)


def change_perms_service(perm_id: uuid, params: dict) -> Response:
    """Изменить настройки доступа"""
    required = Require(**params)
    required.id = perm_id
    db.session.add(required)
    db.session.commit()
    return jsonify(required=required)


def get_perm_user_service(user_id: uuid) -> PermissionShema:
    """Получить настройки доступа"""
    perm = User.query.filter_by(id=user_id).first()
    roles_out = PermissionShema(many=True).dump(perm)
    return roles_out


def set_permission_from_user(user_id: uuid, permissions: str) -> Response:
    """Установить настройки доступа для юзера"""
    user = db.session.query(User).get(user_id)
    permission = Permission.query.filter_by(name=permissions).first()
    if permission is None:
        jsonify(msg=MsgText.ADD_PERMISSION)
    user.permission.append(permission)
    db.session.add(user)
    db.session.commit()
    return jsonify(user=user)


def delete_permission_from_user(user_id, permissions) -> Response:
    """Удалить настройки доступа для юзера"""
    user = db.session.query(User).get(user_id)
    permission = Permission.query.filter_by(name=permissions).first()
    if permission is None:
        return jsonify(msg=MsgText.PERMISSIONS_NOT_FOUND)
    user.permission.remove(permission)
    db.session.add(user)
    db.session.commit()
    return jsonify(msg=MsgText.REMOVE_PERMISSION)

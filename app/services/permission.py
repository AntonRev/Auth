import logging
import uuid

from flask import Blueprint, jsonify, Response
from sqlalchemy.exc import SQLAlchemyError

from api.v1.msg_text import MsgText
from db.db import db
from models.db_models import User, Role, Permission, Require
from models.swagger_schema import PermissionSchema, RequireShema, UserSchema

permission = Blueprint('permission', __name__)
log = logging.getLogger(__name__)


def get_permission_service(perm_id: uuid) -> PermissionSchema:
    """Проверить описание доступа"""
    permission = Permission.query.filter_by(id=perm_id).first()
    return PermissionSchema().dump(permission)


def add_permission_to_role_service(perm_name, role_name, description) -> Response:
    """Добавить доступы к роли"""
    try:
        role = Role.query.filter_by(name=role_name).first()
        permission = Permission(name=perm_name, description=description, role_id=role.id)
        db.session.add(permission)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return PermissionSchema.dump(permission)


def change_perm_service(perm_id: uuid, description: str) -> RequireShema:
    """Изменить доступы юзера"""
    try:
        require = db.session.query(Require).get(perm_id)
        require.description = description
        db.session.add(require)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return RequireShema().dump(require)


def get_permissions_by_user_service(perm_id: uuid) -> [RequireShema]:
    """Получить все доступы юзера"""
    try:
        require = Require.query.filter_by(id=perm_id).all()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return RequireShema(many=True).dump(require)


def create_new_permission_service(perm_name: str, description: str) -> Response:
    """Создать новые настройки доступа"""
    try:
        required = Require(name=perm_name, description=description)
        db.session.add(required)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return RequireShema().dump(required)


def change_permission_service(perm_id: uuid, params: dict) -> RequireShema:
    """Изменить настройки доступа"""
    try:
        required = Require(**params)
        required.id = perm_id
        db.session.add(required)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return RequireShema().dump(required)


def get_permission_by_user_service(user_id: uuid) -> PermissionSchema:
    """Получить настройки доступа по user_id"""
    try:
        permissions = Permission.query.filter_by(user_id=user_id).first()
        if permissions is None:
            return jsonify(msg=MsgText.USER_NOT_FOUND)
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return PermissionSchema(many=True).dump(permissions)


def set_permission_from_user(user_id: uuid, permissions: str) -> UserSchema:
    """Установить настройки доступа для юзера"""
    try:
        user = db.session.query(User).get(user_id)
        permission = Permission.query.filter_by(name=permissions).first()
        if permission is None:
            jsonify(msg=MsgText.PERMISSIONS_NOT_FOUND)
        user.permission.append(permission)
        db.session.add(user)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return UserSchema().dump(user)


def delete_permission_from_user(user_id, permissions) -> Response:
    """Удалить настройки доступа для юзера"""
    try:
        user = db.session.query(User).get(user_id)
        permission = Permission.query.filter_by(name=permissions).first()
        if permission is None:
            return jsonify(msg=MsgText.PERMISSIONS_NOT_FOUND)
        user.permission.remove(permission)
        db.session.add(user)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return jsonify(msg=MsgText.REMOVE_PERMISSION)

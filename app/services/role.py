import logging
import uuid

from flask import Blueprint, jsonify, Response
from sqlalchemy.exc import SQLAlchemyError

from api.v1.msg_text import MsgText
from db.db import db
from models.db_models import User, Role, Permission
from models.swagger_schema import RoleSchema, PermissionSchema, UserSchema

rol = Blueprint('rol', __name__)
log = logging.getLogger(__name__)


def get_permissions_by_role(role_name: str) -> [PermissionSchema]:
    """Получить доступы по роли"""
    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        return jsonify(msg=MsgText.ROLE_NOT_FOUND)
    permissions = Permission.query.filter_by(role_id=role.id).all()
    return PermissionSchema(many=True).dump(permissions)


def add_rol_service(role: str, description: str) -> RoleSchema:
    """Создать роль"""
    try:
        role = Role(name=role, description=description)
        db.session.add(role)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return RoleSchema().dump(role)


def change_rol_service(role: str, description: str) -> RoleSchema:
    """Изменить роль"""
    try:
        change_role = Role.query.filter_by(name=role).first()
        change_role.description = description
        if change_role is None:
            return jsonify(msg=MsgText.ROLE_NOT_FOUND)
        db.session.add(change_role)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return RoleSchema().dump(change_role)


def delete_rol_service(role: str) -> Response:
    """Удалить роль"""
    try:
        change_role = Role.query.filter_by(name=role).first()
        if change_role is None:
            return jsonify(msg=MsgText.ROLE_NOT_FOUND)
        db.session.delete(rol)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return jsonify(msg=MsgText.DELETE)


def get_role_by_user_service(user_id: uuid) -> RoleSchema:
    """Получить роли юзера"""
    try:
        if (type(user_id)) != uuid:
            user = User.query.filter_by(email=user_id).first()
        else:
            user = User.query.filter_by(id=user_id).first()
        if user is None:
            return jsonify(msg=MsgText.ROLE_NOT_FOUND)
        change_role = user.role
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return RoleSchema(many=True).dump(change_role)


def add_permission_to_role_service(permission_id: uuid, role_id: uuid) -> PermissionSchema:
    """Добавить доступы к роли"""
    try:
        role = Role.query.filter_by(id=role_id).first()
        permission = Permission.query.filter_by(id=permission_id).first()
        role.permissions.add(permission)
        db.session.add(role)
        db.session.commit()
    except SQLAlchemyError:
        log.exception("Error adding permission to role.")
        return jsonify(msg=MsgText.ERROR_BD)
    return PermissionSchema().dump(permission)


def set_role_by_user_service(user_id: uuid, roles: str) -> UserSchema:
    """Установить роли для юзера"""
    try:
        user = db.session.query(User).get(user_id)
        change_role = Role.query.filter_by(name=roles).first()
        user.role.append(change_role)
        db.session.add(user)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return UserSchema().dump(user)


def delete_role_by_user_service(user_id: uuid, roles: str) -> Response:
    """Удалить роли для юзера"""
    try:
        user = db.session.query(User).get(user_id)
        rol = Role.query.filter_by(name=roles).first()
        if rol is None:
            return jsonify(msg=MsgText.NOT_ACCSESS)
        user.role.remove(rol)
        db.session.add(user)
        db.session.commit()
    except SQLAlchemyError:
        return jsonify(msg=MsgText.ERROR_BD)
    return jsonify(msg=MsgText.REMOVE)

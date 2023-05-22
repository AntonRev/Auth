import logging
import uuid

from flask import Blueprint, jsonify

from api.v1.msg_text import MsgText
from db.db import db
from models.db_models import User, Role, Permission
from models.schema import RoleSchema, PermissionShema

rol = Blueprint('rol', __name__)
log = logging.getLogger(__name__)


def get_permissions(role_name: str) -> PermissionShema:
    """Получить доступы по роли"""
    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        return []
    permissions = Permission.query.filter_by(role_id=role.id).all()
    permissions_out = PermissionShema(many=True).dump(permissions)
    return permissions_out


def add_rol_service(role: str, description: str) -> bool:
    """Создать роль"""
    role = Role(name=role, description=description)
    db.session.add(role)
    db.session.commit()
    return jsonify(role=role)


def change_rol_service(role: str, description: str) -> bool:
    """Изменить роль"""
    rol = Role.query.filter_by(name=role).first()
    rol.description = description
    db.session.add(rol)
    db.session.commit()
    return jsonify(role=role)


def delete_rol_service(role: str) -> bool:
    """Удалить роль"""
    role = Role.query.filter_by(name=role).first()
    if rol is None:
        return jsonify(msg=MsgText.NOT_ACCSESS)
    try:
        db.session.delete(rol)
        db.session.commit()
    except:
        return jsonify(msg=MsgText.NOT_ACCSESS)
    return jsonify(msg=MsgText.DELETE)


def get_ros_service(user_id: uuid) -> RoleSchema:
    """Получить роли юзера"""
    if (type(user_id)) != uuid:
        user = User.query.filter_by(email=user_id).first()
    else:
        user = User.query.filter_by(id=user_id).first()
    if user is None:
        return []
    rol = user.role
    roles_out = RoleSchema(many=True).dump(rol)
    return roles_out


def set_roles_service(user_id: uuid, roles: str) -> None:
    """Установить роли для юзера"""
    user = db.session.query(User).get(user_id)
    rol = Role.query.filter_by(name=roles).first()
    user.role.append(rol)
    db.session.add(user)
    db.session.commit()
    return jsonify(user=user)

def delete_rols_service(user_id: uuid, roles: str) -> bool:
    """Удалить роли для юзера"""
    user = db.session.query(User).get(user_id)
    rol = Role.query.filter_by(name=roles).first()
    if rol is None:
        return jsonify(msg=MsgText.NOT_ACCSESS)
    user.role.remove(rol)
    db.session.add(user)
    db.session.commit()
    return jsonify(msg=MsgText.REMOVE)

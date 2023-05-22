import logging
import uuid

from flask import Blueprint

from db.db import db
from models.db_models import User, Role, Permission
from models.schema import RoleSchema, PermissionShema

rol = Blueprint('rol', __name__)
log = logging.getLogger(__name__)


def get_permissions(role_name: str):
    """Получить доступы по роли"""
    role = Role.query.filter_by(name=role_name).first()
    if role is None:
        return []
    permissions = Permission.query.filter_by(role_id=role.id).all()
    permissions_out = PermissionShema(many=True).dump(permissions)
    return permissions_out


def add_rol_service(role: str, description: str):
    """Создать роль"""
    role = Role(name=role, description=description)
    db.session.add(role)
    db.session.commit()
    return True


def change_rol_service(role: str, description: str):
    """Изменить роль"""
    rol = Role.query.filter_by(name=role).first()
    rol.description = description
    db.session.add(rol)
    db.session.commit()
    return True


def delete_rol_service(role: str) -> bool:
    """Удалить роль"""
    rol = Role.query.filter_by(name=role).first()
    try:
        if rol is None:
            return False
        db.session.delete(rol)
        db.session.commit()
    except:
        return False
    return True



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


def delete_rols_service(user_id: uuid, roles: str):
    """Удалить роли для юзера"""
    user = db.session.query(User).get(user_id)
    rol = Role.query.filter_by(name=roles).first()
    if rol is None:
        return False
    user.role.remove(rol)
    db.session.add(user)
    db.session.commit()
    return True

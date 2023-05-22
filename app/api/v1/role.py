import http
import logging
from uuid import uuid4

from flask import jsonify, request, Blueprint
from flask_apispec import use_kwargs, doc, marshal_with
from webargs import fields

from models.swagger_schema import PermissionShema, RoleSchema, RespSchema, UserSchema
from services.role import get_permissions, add_rol_service, change_rol_service, delete_rol_service, get_ros_service, \
    set_roles_service, delete_rols_service
from utils.check import check_roles

rol = Blueprint('rol', __name__)
log = logging.getLogger(__name__)


@doc(description='Возвращает описание и список доступов для роли', tags=['Role'])
@marshal_with(PermissionShema(many=True))
@check_roles(roles=['admin'])
@rol.route('/<role_name>', methods=['GET'])
def get_role(role_name: str):
    """Возвращает описание и список доступов для роли"""
    permissions_out = get_permissions(role_name)
    return jsonify(permissions_out)


@doc(description='Добавить новую роль', tags=['Role'])
@check_roles(roles=['admin'])
@marshal_with(RoleSchema())
@use_kwargs({'description': fields.Str()})
@rol.route('/<role>', methods=['POST'])
def add_role(role: str):
    """Добавить новую роль"""
    description = request.args.get('description', default=None)
    return add_rol_service(role, description)


@doc(description='Изменить роль', tags=['Role'])
@marshal_with(RoleSchema())
@use_kwargs({'description': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/<role>', methods=['PUT'])
def change_role(role: str):
    """Изменить роль"""
    description = request.json['description']
    return change_rol_service(role, description)


@doc(description='Удалить роль по названию', tags=['Role'])
@check_roles(roles=['admin'])
@marshal_with(RespSchema())
@rol.route('/<role>', methods=['DELETE'])
def delete_role(role: str):
    """Удаление роли"""
    return delete_rol_service(role)


@doc(description='Возвращает список ролей юзера', tags=['Role'])
@marshal_with(RoleSchema(many=True))
@rol.route('/user/<user_id>', methods=['GET'])
def get_roles(user_id: uuid4):
    """Возвращает список ролей юзера"""
    roles_out = get_ros_service(user_id)
    return jsonify(roles_out)


@doc(description='Добавить роль для юзера', tags=['Role'])
@marshal_with(UserSchema())
@use_kwargs({'role': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/user/<user_id>', methods=['POST'])
def set_roles(user_id: uuid4):
    """Добавить роль для юзера"""
    roles = request.json['role']
    return set_roles_service(user_id, roles)


@doc(description='Удалить роль у юзера', tags=['Role'])
@marshal_with(UserSchema())
@use_kwargs({'role': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/user/<user_id>', methods=['DELETE'])
def delete_roles(user_id: uuid4):
    """Удалить роль у юзера"""
    roles = request.json['role']
    return delete_rols_service(user_id, roles)


@rol.errorhandler(Exception)
def handle_exception(e):
    """Возвращает JSON вместо HTML для ошибок HTTP"""
    user_request = request.json
    log.warning("Exception: %s - Request: %s" % (str(e), str(user_request)))
    # заменяем тело ответа сервера на JSON
    return jsonify(Error=str(e)), http.HTTPStatus.BAD_REQUEST

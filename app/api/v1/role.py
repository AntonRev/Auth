import http
import logging
from uuid import uuid4

from flask import jsonify, request, Blueprint
from flask_apispec import use_kwargs, doc, marshal_with
from webargs import fields

from models.swagger_schema import PermissionSchema, RoleSchema, RespSchema, UserSchema
from services.role import get_permissions_by_role, add_rol_service, change_rol_service, delete_rol_service, \
    set_role_by_user_service, delete_role_by_user_service, get_role_by_user_service, add_permission_to_role_service
from utils.check import check_roles

rol = Blueprint('rol', __name__)
log = logging.getLogger(__name__)


@doc(description='Возвращает описание и список доступов для роли', tags=['Role'])
@marshal_with(PermissionSchema(many=True))
@check_roles(roles=['admin'])
@rol.route('/<string:role_name>', methods=['GET'])
def get_role(role_name: str):
    """Возвращает список доступов для роли"""
    return get_permissions_by_role(role_name)


@doc(description='Добавить новую роль', tags=['Role'])
@check_roles(roles=['admin'])
@marshal_with(RoleSchema())
@use_kwargs({'description': fields.Str()})
@rol.route('/<string:role>', methods=['POST'])
def add_role(role: str):
    """Добавить новую роль"""
    description = request.json['description']
    return add_rol_service(role, description)


@doc(description='Изменить роль', tags=['Role'])
@marshal_with(RoleSchema())
@use_kwargs({'description': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/<string:role>', methods=['PUT'])
def change_role(role: str):
    """Изменить роль"""
    description = request.json['description']
    return change_rol_service(role, description)


@doc(description='Удалить роль по названию', tags=['Role'])
@check_roles(roles=['admin'])
@marshal_with(RespSchema())
@rol.route('/<string:role>', methods=['DELETE'])
def delete_role(role: str):
    """Удаление роли"""
    return delete_rol_service(role)


@doc(description='Возвращает список ролей юзера', tags=['Role'])
@marshal_with(RoleSchema(many=True))
@rol.route('/user/<uuid:user_id>', methods=['GET'])
def get_roles(user_id: uuid4):
    """Возвращает список ролей юзера"""
    return get_role_by_user_service(user_id)



@doc(description='Добавить роль для юзера', tags=['Role'])
@marshal_with(UserSchema())
@use_kwargs({'role': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/user/<uuid:user_id>', methods=['POST'])
def set_roles_by_user(user_id: uuid4):
    """Добавить роль для юзера"""
    roles = request.json['role']
    return set_role_by_user_service(user_id, roles)


@doc(description='Удалить роль у юзера', tags=['Role'])
@marshal_with(UserSchema())
@use_kwargs({'role': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/user/<uuid:user_id>', methods=['DELETE'])
def delete_role_by_user(user_id: uuid4):
    """Удалить роль у юзера"""
    roles = request.json['role']
    return delete_role_by_user_service(user_id, roles)

@doc(description='Добавить права доступа для роли', tags=['Permission'])
@marshal_with(PermissionSchema)
@use_kwargs({'permission_id': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/<uuid:role_id>/permission', methods=['POST'])
def add_permission_to_role(role_id):
    """Добавить доступы к роли"""
    permission_id = request.json['permission_id']
    return add_permission_to_role_service(role_id, permission_id)


@rol.errorhandler(Exception)
def handle_exception(e):
    """Возвращает JSON вместо HTML для ошибок HTTP"""
    user_request = request.json
    log.warning("Exception: %s - Request: %s" % (str(e), str(user_request)))
    # заменяем тело ответа сервера на JSON
    return jsonify(Error=str(e)), http.HTTPStatus.BAD_REQUEST

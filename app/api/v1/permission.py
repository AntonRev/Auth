import http
import logging
import uuid

from flask import jsonify, request, Blueprint, Response
from flask_apispec import use_kwargs, doc, marshal_with
from webargs import fields

from models.swagger_schema import PermissionSchema, RequireShema, RespSchema, UserSchema
from services.permission import get_permission_service, get_permissions_by_user_service, \
    create_new_permission_service, change_permission_service, get_permission_by_user_service, set_permission_from_user, \
    delete_permission_from_user
from utils.check import check_roles

permission = Blueprint('permission', __name__)
log = logging.getLogger(__name__)


@doc(description='Получить описание доступа', tags=['Permission'])
@marshal_with(PermissionSchema)
@permission.route('/<uuid:perm_id>>', methods=['GET'])
def get_perm(perm_id):
    """Получить описание доступа"""
    permissions_out = get_permission_service(perm_id)
    return jsonify(permissions_out)


@doc(description='Изменить описание прав доступа', tags=['Permission'])
@marshal_with(RequireShema)
@use_kwargs({'description': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/<uuid:perm_id>', methods=['PUT'])
def change_permission(perm_id):
    change_params = request.json
    require_out = change_permission_service(perm_id, change_params)
    return jsonify(require_out)


@doc(description='Получить права доступа', tags=['Permission'])
@marshal_with(RequireShema)
@permission.route('/user/<uuid:perm_id>', methods=['GET'])
def get_perms(perm_id):
    require_out = get_permissions_by_user_service(perm_id)
    return jsonify(require_out)


@doc(description='Создать права доступа', tags=['Permission'])
@marshal_with(RequireShema)
@use_kwargs({'description': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/<uuid:perm_id>', methods=['POST'])
def add_perms(perm_name):
    """Установить требуемые права доступа"""
    params = request.json
    return create_new_permission_service(perm_name, params['description'])


@doc(description='Изменить описание прав доступа', tags=['Permission'])
@marshal_with(RequireShema)
@check_roles(roles=['admin'])
@permission.route('/<uuid:perm_id>', methods=['PUT'])
def change_perms(perm_id: uuid):
    """Изменить правa доступа"""
    params = request.json
    return change_permission_service(perm_id, params)


@doc(description='Возвращает список доступов юзера', tags=['Permission'])
@marshal_with(PermissionSchema)
@permission.route('/user/<uuid:user_id>', methods=['GET'])
def get_perm_user(user_id):
    """Возвращает список доступов юзера"""
    roles_out = get_permission_by_user_service(user_id)
    return jsonify(roles_out)


@doc(description='Добавить доступ для юзера', tags=['Permission'])
@marshal_with(UserSchema)
@use_kwargs({'permissions': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/user/<uuid:user_id>', methods=['POST'])
def set_perm_user(user_id) -> Response:
    """Добавить доступ для юзера"""
    permission_name = request.json['permissions']
    return set_permission_from_user(user_id, permission_name)


@doc(description='Удалить доступ для юзера', tags=['Permission'])
@marshal_with(RespSchema)
@use_kwargs({'permissions': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/user/<uuid:user_id>', methods=['DELETE'])
def delete_perm_user(user_id):
    permission_name = request.json['permissions']
    return delete_permission_from_user(user_id, permission_name)


@permission.errorhandler(Exception)
def handle_exception(e):
    """Возвращает JSON вместо HTML для ошибок HTTP"""
    user_request = request.json
    log.warning("Exception: %s - Request: %s" % (str(e), str(user_request)))
    # заменяем тело ответа сервера на JSON
    return jsonify(Error=str(e)), http.HTTPStatus.BAD_REQUEST

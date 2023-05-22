import http
import logging

from flask import jsonify, request, Blueprint
from flask_apispec import use_kwargs, doc, marshal_with
from webargs import fields

from api.v1.msg_text import MsgText
from models.schema import PermissionShema, RequireShema, RespSchema
from services.permission import get_perm_service, add_perm_service, change_perm_service, get_perms_service, \
    add_perms_service, change_perms_service, get_perm_user_service, set_permission_from_user, \
    delete_permission_from_user
from utils.check import check_roles

permission = Blueprint('permission', __name__)
log = logging.getLogger(__name__)


@doc(description='Получить описание доступа', tags=['Permission'])
@marshal_with(PermissionShema)
@permission.route('/<perm_id>', methods=['GET'])
def get_perm(perm_id):
    """Получить описание доступа"""
    permissions_out = get_perm_service(perm_id)
    return jsonify(permissions_out)


@doc(description='Создать новый доступ', tags=['Permission'])
@marshal_with(RespSchema)
@use_kwargs({'description': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/<perm_name>', methods=['POST'])
def add_perm(perm_name):
    """Добавить доступы к роли"""
    params = request.json
    role = params['role_name']
    perm = params['description']
    return add_perm_service(perm_name, role, perm)


@doc(description='Изменить описание доступа', tags=['Permission'])
@marshal_with(RequireShema)
@use_kwargs({'description': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/<perm_id>', methods=['PUT'])
def change_perm(perm_id):
    params = request.json
    require_out = change_perm_service(perm_id, params['description'])
    return jsonify(require_out)


@doc(description='Получить требуемые права доступа', tags=['Permission'])
@marshal_with(RequireShema)
@permission.route('/required/<perm_id>', methods=['GET'])
def get_perms(perm_id):
    require_out = get_perms_service(perm_id)
    return jsonify(require_out)


@doc(description='Установить требуемые права доступа', tags=['Permission'])
@marshal_with(RespSchema)
@use_kwargs({'description': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/required/<perm_name>', methods=['POST'])
def add_perms(perm_name):
    """Установить требуемые права доступа"""
    params = request.json
    return add_perms_service(perm_name, params['description'])


@doc(description='Изменить описание прав доступа', tags=['Permission'])
@marshal_with(RespSchema)
@check_roles(roles=['admin'])
@permission.route('/required/<perm_id>', methods=['PUT'])
def change_perms(perm_id):
    """Изменить правa доступа"""
    params = request.json
    return change_perms_service(perm_id, params)


@doc(description='Возвращает список доступов юзера', tags=['Permission'])
@marshal_with(PermissionShema)
@permission.route('/user/<user_id>', methods=['GET'])
def get_perm_user(user_id):
    """Возвращает список доступов юзера"""
    roles_out = get_perm_user_service(user_id)
    return jsonify(roles_out)


@doc(description='Добавить доступ для юзера', tags=['Permission'])
@marshal_with(RespSchema)
@use_kwargs({'permissions': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/user/<user_id>', methods=['POST'])
def set_perm_user(user_id):
    """Добавить доступ для юзера"""
    permission_name = request.json['permissions']
    return set_permission_from_user(user_id, permission_name)


@doc(description='Удалить доступ для юзера', tags=['Permission'])
@marshal_with(RespSchema)
@use_kwargs({'permissions': fields.Str()})
@check_roles(roles=['admin'])
@permission.route('/user/<user_id>', methods=['DELETE'])
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

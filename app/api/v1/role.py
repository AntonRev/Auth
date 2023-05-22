import http
import logging
from uuid import uuid4

from flask import jsonify, request, Blueprint
from flask_apispec import use_kwargs, doc, marshal_with
from webargs import fields

from api.v1.msg_text import MsgText
from models.schema import PermissionShema, RoleSchema, RespSchema
from services.role import get_permissions, add_rol_service, change_rol_service, delete_rol_service, get_ros_service, \
    set_roles_service, delete_rols_service
from utils.check import check_roles

rol = Blueprint('rol', __name__)
log = logging.getLogger(__name__)


@doc(description='Возвращает описание и список доступов для роли', tags=['Role'])
@marshal_with(PermissionShema)
@check_roles(roles=['admin'])
@rol.route('/<role_name>', methods=['GET'])
def get_role(role_name: str):
    """Возвращает описание и список доступов для роли"""
    permissions_out = get_permissions(role_name)
    return jsonify(permissions_out)


@doc(description='Добавить новую роль', tags=['Role'])
@check_roles(roles=['admin'])
@marshal_with(RespSchema)
@use_kwargs({'description': fields.Str()})
@rol.route('/<role>', methods=['POST'])
def add_role(role: str):
    """Добавить новую роль"""
    description = request.args.get('description', default=None)
    msg = MsgText.NOT_ACCSESS
    if add_rol_service(role, description):
        msg = MsgText.CREATE
    return jsonify(msg=msg)


@doc(description='Изменить роль', tags=['Role'])
@marshal_with(RespSchema)
@use_kwargs({'description': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/<role>', methods=['PUT'])
def change_role(role: str):
    """Изменить роль"""
    description = request.json['description']
    msg = MsgText.NOT_ACCSESS
    if change_rol_service(role, description):
        msg = MsgText.CREATE
    return jsonify(msg=msg)


@doc(description='Удалить роль по названию', tags=['Role'])
@check_roles(roles=['admin'])
@marshal_with(RespSchema)
@rol.route('/<role>', methods=['DELETE'])
def delete_role(role: str):
    msg = MsgText.NOT_ACCSESS
    if delete_rol_service(role):
        msg = MsgText.DELETE
    return jsonify(msg=msg)


@doc(description='Возвращает список ролей юзера', tags=['Role'])
@marshal_with(RoleSchema)
@rol.route('/user/<user_id>', methods=['GET'])
def get_roles(user_id: uuid4):
    """Возвращает список ролей юзера"""
    roles_out = get_ros_service(user_id)
    return jsonify(roles_out)


@doc(description='Добавить роль для юзера', tags=['Role'])
@marshal_with(RespSchema)
@use_kwargs({'role': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/user/<user_id>', methods=['POST'])
def set_roles(user_id: uuid4):
    """Добавить роль для юзера"""
    roles = request.json['role']
    if set_roles_service(user_id, roles):
        return jsonify(msg=MsgText.ADD)
    return jsonify(msg=MsgText.NOT_ACCSESS)


@doc(description='Удалить роль у юзера', tags=['Role'])
@marshal_with(RespSchema)
@use_kwargs({'role': fields.Str()})
@check_roles(roles=['admin'])
@rol.route('/user/<user_id>', methods=['DELETE'])
def delete_roles(user_id: uuid4):
    """Удалить роль у юзера"""
    roles = request.json['role']
    msg = MsgText.NOT_ACCSESS
    if delete_rols_service(user_id, roles):
        msg = MsgText.REMOVE
    return jsonify(msg=msg)


@rol.errorhandler(Exception)
def handle_exception(e):
    """Возвращает JSON вместо HTML для ошибок HTTP"""
    user_request = request.json
    log.warning("Exception: %s - Request: %s" % (str(e), str(user_request)))
    # заменяем тело ответа сервера на JSON
    return jsonify(Error=str(e)), http.HTTPStatus.BAD_REQUEST

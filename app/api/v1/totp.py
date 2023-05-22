import logging

from flask import redirect, url_for, jsonify, request, Blueprint
from flask_apispec import doc, marshal_with, use_kwargs
from flask_jwt_extended import jwt_required, verify_jwt_in_request, get_jwt_identity
from webargs import fields

from api.v1.msg_text import MsgText
from models.schema import TokenSchema
from services.totp import sync_service, sync_check_totp, check_totp_service
from utils.rate_limit import ratelimit

totp = Blueprint('totp', __name__)
log = logging.getLogger(__name__)


@doc(description='Установить 2 факторную авторизацию для зарегестрированого пользователя, Возвращает шаблон с QR',
     tags=['TOTP'])
@totp.route('/set_two_factor', methods=['POST'])
@jwt_required()
def sync():
    """Установить 2 факторную авторизацию для зарегестрированого пользователя"""
    verify_jwt_in_request()
    user_id = get_jwt_identity()
    tmpl = sync_service(user_id)
    return tmpl


@doc(description='Проверка кода при синхронизации с TOPT приложением', tags=['TOTP'])
@totp.route("/sync", methods=['POST'])
@ratelimit()
@jwt_required()
def sync_check():
    """Проверка кода при синхронизации с TOPT приложением"""
    verify_jwt_in_request()
    user_id = get_jwt_identity()
    code = request.json['code']
    if sync_check_totp(user_id, code):
        return redirect(url_for('user.index'))
    return jsonify(msg=MsgText.BED_CODE)


@doc(description='Проверка кода при авторизации и выдача токенов', tags=['TOTP'])
@use_kwargs({'code': fields.Str()})
@marshal_with(TokenSchema)
@ratelimit()
@totp.route('/check/<email>', methods=['POST'])
def check(email: str):
    """Проверка кода при авторизации и выдача токенов"""
    code = request.json['code']
    msg = check_totp_service(email, code)
    return jsonify(msg)

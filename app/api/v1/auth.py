import http
import logging

from flask import jsonify, request, Blueprint
from flask_apispec import use_kwargs, doc, marshal_with
from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt
from webargs import fields

from api.v1.msg_text import MsgText
from config.config import Config
from db.jwt_db import jwt_db
from models.schema import TokenSchema, RespSchema
from services.auth import login_service, refresh_service, del_ua_in_user, signup_service
from utils.rate_limit import ratelimit

auth = Blueprint('auth', __name__)
log = logging.getLogger(__name__)

# JWT
ACCESS_EXPIRES = Config().JWT_ACCESS_TOKEN_EXPIRES
jwt_blocklist = jwt_db


@doc(description='Вход пользователя. При включеной 2 факторной авторизации перенапраляет на запрос запрос пароля',
     tags=['Authorization'])
@use_kwargs({'email': fields.Str(), 'password': fields.Str()})
@marshal_with(TokenSchema)
@auth.route('/login', methods=['POST'])
@ratelimit()
def login(**kwargs):
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    ua = request.headers.get('User-Agent')
    msg = login_service(email, password, ua)
    return jsonify(msg)


@doc(description='Обновление токена. При запросе проверяется User-Agent в истории', tags=['Authorization'])
@marshal_with(TokenSchema)
@auth.route('/refresh', methods=['POST', 'GET'])
@jwt_required(refresh=True)
def refresh(**kwargs):
    ua = request.headers.get('User-Agent')
    id = get_jwt_identity()
    role = get_jwt()['role']
    msg = refresh_service(id, ua, role)
    return jsonify(msg)


@doc(description='Выход пользователя', tags=['Authorization'])
@marshal_with(RespSchema)
@auth.route("/logout", methods=["DELETE"])
@jwt_required()
def logout():
    id = get_jwt_identity()
    ua = request.headers.get('User-Agent')
    del_ua_in_user(id, ua)
    jti = get_jwt()["jti"]
    jwt_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
    return jsonify(msg=MsgText.ACCESS_TOKEN_REVOKED)


@doc(description='Регистрация пользователя', tags=['Authorization'])
@use_kwargs({'email': fields.Str(), 'password1': fields.Str(), 'password2': fields.Str(), 'age': fields.Int()})
@marshal_with(TokenSchema)
@auth.route('/signup', methods=['POST'])
@ratelimit()
def signup_post(**kwargs):
    username = request.json.get("email", None)
    password = request.json.get("password1", None)
    password2 = request.json.get("password2", None)
    age = request.json.get("age", None)
    ua = request.headers.get('User-Agent')
    msg = signup_service(username, password, password2, ua, age)
    return jsonify(msg)


@auth.errorhandler(422)
def handle_error(err):
    headers = err.data.get('headers', None)
    messages = err.data.get('msg', ['Invalid Request.'])
    log.warning('Invalid input params: %s' % messages)
    if headers:
        return jsonify({'msg': messages}), http.HTTPStatus.BAD_REQUEST, headers
    else:
        return jsonify({'msg': messages}), http.HTTPStatus.BAD_REQUEST


@auth.errorhandler(Exception)
def handle_exception(e):
    """Возвращает JSON вместо HTML для ошибок HTTP"""
    user_request = request.json
    log.warning("Exception: %s - Request: %s" % (str(e), str(user_request)))
    # заменяем тело ответа сервера на JSON
    return jsonify(Error=str(e)), http.HTTPStatus.BAD_REQUEST

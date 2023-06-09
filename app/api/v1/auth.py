import http
import logging

from flask import jsonify, request, Blueprint, Response
from flask_apispec import use_kwargs, doc, marshal_with
from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt
from webargs import fields

from api.v1.msg_text import MsgText
from config.config import Config, config
from db.jwt_db import jwt_db
from models.swagger_schema import TokenSchema, RespSchema
from services.auth import login_service, refresh_service, del_ua_in_user, signup_service
from utils.rate_limit import ratelimit

auth = Blueprint('auth', __name__)
log = logging.getLogger(__name__)

# JWT
ACCESS_EXPIRES = Config().JWT_ACCESS_TOKEN_EXPIRES
jwt_blocklist = jwt_db


@doc(description='Авторизация пользователя. При включеной 2 факторной авторизации перенапраляет на запрос пароля',
     tags=['Authorization'])
@use_kwargs({'email': fields.Str(), 'password': fields.Str()})
@marshal_with(TokenSchema())
@auth.route('/login', methods=['POST'])
@ratelimit()
def login(**kwargs) -> Response:
    """Вход пользователя
    При включеной 2-факторной авторизации перенапраляет на запрос пароля"""
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    ua = request.headers.get('User-Agent')
    return login_service(email, password, ua)


@doc(description='Получить OPEN TOKEN JWT',
     tags=['Authorization'])
@marshal_with(TokenSchema(only=('access_token',)))
@auth.route('/open-token', methods=['GET'])
def get_open_token() -> Response:
    """Получить OPEN TOKEN JWT'"""
    return jsonify(token=config.JWT_OPEN_KEY)


@doc(description='Обновление токена.', tags=['Authorization'])
@marshal_with(TokenSchema())
@auth.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh(**kwargs) -> Response:
    """Обновление токена"""
    ua = request.headers.get('User-Agent')
    id = get_jwt_identity()
    role = get_jwt()['role']
    return refresh_service(id, ua, role)


@doc(description='Выход пользователя', tags=['Authorization'])
@marshal_with(RespSchema())
@auth.route("/logout", methods=["DELETE"])
@jwt_required()
def logout():
    """Выход пользователя"""
    id = get_jwt_identity()
    ua = request.headers.get('User-Agent')
    del_ua_in_user(id, ua)
    jti = get_jwt()["jti"]
    jwt_blocklist.set(jti, "", ex=ACCESS_EXPIRES)
    return jsonify(msg=MsgText.ACCESS_TOKEN_REVOKED)


@doc(description='Регистрация пользователя', tags=['Authorization'])
@use_kwargs({'email': fields.Str(), 'password1': fields.Str(), 'password2': fields.Str(), 'age': fields.Int()})
@marshal_with(TokenSchema())
@auth.route('/signup', methods=['POST'])
@ratelimit()
def signup_post(**kwargs):
    """Регистрация пользователя"""
    username = request.json.get("email", None)
    password = request.json.get("password1", None)
    password2 = request.json.get("password2", None)
    age = request.json.get("age", None)
    ua = request.headers.get('User-Agent')
    return signup_service(username, password, password2, ua, age)


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

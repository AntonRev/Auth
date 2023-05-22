import http
import logging

from flask import jsonify, Blueprint, request
from flask_apispec import doc, marshal_with
from flask_jwt_extended import get_jwt_identity, jwt_required

from db.jwt_db import jwt_db
from models.swagger_schema import UserSchema, UserAgentShema
from services.user import users_service, index_service, history_service

user = Blueprint('user', __name__)
log = logging.getLogger(__name__)

# Config
ACCESS_EXPIRES = 120

# JWT
jwt_blocklist = jwt_db


@doc(description='Вывод всех польователей', tags=['User'])
@user.route('/all', methods=['GET'])
@marshal_with(UserSchema(many=True, only=('id', 'login', 'email')))
@jwt_required()
def users():
    """Вывод всех польователей"""
    us_all = users_service()
    return jsonify(us_all)


@doc(description='Страница пользователя', tags=['User'])
@marshal_with(UserSchema(only=("id", "login", "email", 'auth_two_factor')))
@user.route("/index", methods=["GET"])
@jwt_required()
def index():
    """Страница пользователя"""
    id = get_jwt_identity()
    user_out = index_service(id)
    return jsonify(user_out)


@doc(description='Страница с историей входов. Указываются только устройства с которых заходили', tags=['User'])
@marshal_with(UserAgentShema())
@user.route("/history", methods=["GET"])
@jwt_required()
def history():
    """История входов"""
    page = request.args.get('page')
    per_page = request.args.get('per_page')
    id = get_jwt_identity()
    user_agent = history_service(id, page, per_page)
    return jsonify(user_agent)


@user.errorhandler(422)
def handle_error(err):
    headers = err.data.get('headers', None)
    messages = err.data.get('msg', ['Invalid Request.'])
    log.warning(f'Invalid input params: {messages}')
    if headers:
        return jsonify({'msg': messages}), http.HTTPStatus.BAD_REQUEST, headers
    else:
        return jsonify({'msg': messages}), http.HTTPStatus.BAD_REQUEST


@user.errorhandler(Exception)
def handle_exception(e):
    """Возвращает JSON вместо HTML для ошибок HTTP"""
    user_request = request.json
    log.warning("Exception: %s - Request: %s" % (str(e), str(user_request)))
    # заменяем тело ответа сервера на JSON
    return jsonify(Error=str(e)), 400

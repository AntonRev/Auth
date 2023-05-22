import logging
from enum import Enum

from flask import redirect, jsonify, Blueprint, request
from flask_apispec import doc

from services.oauth import Yandex, Vk, set_auth_servie
from utils.circuit_breaker import circuitbreakers
from utils.tracer import tracer

oauth = Blueprint('oauth', __name__)
log = logging.getLogger(__name__)


class NameOauth(Enum):
    YANDEX = 'yandex'
    VK = 'VK'


@doc(description='Запрос авторизации', tags=['OAuth'])
@oauth.route('/<auth_name>', methods=['POST', 'GET'])
@tracer
@circuitbreakers(redirect_to='user.index')
def set_auth(auth_name):
    """Запрос авторизации"""
    url = set_auth_servie(auth_name)
    return redirect(url)


@doc(description='Получение токена и получение данных', tags=['OAuth'])
@oauth.route('/<auth_name>/<code>', methods=['GET'])
@tracer
def get_auth(auth_name, code):
    """Получение токена и получение данных"""
    ua = request.headers.get('User-Agent')
    if auth_name == NameOauth.YANDEX:
        aoth = Yandex()
    if auth_name == NameOauth.VK:
        aoth = Vk()
    token = aoth.get_token_service(code)
    msg = aoth.get_data_service(token, ua)
    return jsonify(msg)

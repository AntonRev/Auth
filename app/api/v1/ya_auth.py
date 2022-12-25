import logging

from flask import redirect, jsonify, Blueprint, request, url_for
from flask_apispec import doc

from services.ya_auth import set_auth_servie, get_data_service, get_token_service
from utils.circuit_breaker import circuitbreakers
from utils.tracer import tracer

ya_auth = Blueprint('auth_ya', __name__)
log = logging.getLogger(__name__)


@doc(description='Запрос авторизации через Яндекс', tags=['Auth_yandex'])
@ya_auth.route('/set_auth_ya', methods=['POST', 'GET'])
@tracer
@circuitbreakers(redirect_to='user.index')
def set_auth():
    url = set_auth_servie()
    return redirect(url)


@doc(description='Получение токена и перенаправление для получение данных',
     tags=['Auth_yandex'])
@ya_auth.route('/get_auth/<code>', methods=['GET'])
@tracer
def get_auth(code):
    token = get_token_service(code)
    return redirect(url_for('ya_auth.get_data') + f'?token={token}')


@doc(description='Регистрация через Яндекс по токену.', tags=['Auth_yandex'])
@ya_auth.route('/get_data', methods=['GET'])
@tracer
def get_data():
    token = request.args.get('token')
    ua = request.headers.get('User-Agent')
    msg = get_data_service(token, ua)
    return jsonify(msg)

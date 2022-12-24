import base64
import logging
import uuid

import requests
from flask import Blueprint

from config.config import config
from db.db import db
from models.db_models import Auth2, User
from services.auth import add_ua_user, create_token

redirect_uri = 'https://oauth.yandex.ru/verification_code'

ya_auth = Blueprint('auth_ya', __name__)
log = logging.getLogger(__name__)
client_id = config.CLIENT_ID


def set_auth_servie():
    url = f'https://oauth.yandex.ru/authorize?response_type=token&client_id={client_id}&redirect_uri={redirect_uri}&display=popup'
    return url


def get_token_service(code):
    url = 'https://oauth.yandex.ru'
    authorization = base64.b64encode(bytes(f'{config.CLIENT_ID}:{config.CLIENT_SECRET}', 'utf-8'))
    headers = {'Authorization': ("Basic " + authorization.decode("utf-8"))}
    response = requests.post(url=url, headers=headers, data={'grant_type': 'authorization_code', 'code': code}).json
    return response['access_token']


def get_data_service(token, ua):
    url = 'https://login.yandex.ru/info'
    headers = {'Authorization': f'OAuth {token}'}
    response = requests.options(url=url, headers=headers).json()
    email = response['default_email']
    user = User.query.filter_by(email=email).first()
    if user is None:
        user = User(email=email, password=uuid.uuid4().hex)
        db.session.add(user)
        db.session.commit()
        user = User.query.filter_by(email=email).first()
    auth = Auth2(token, user.id)
    db.session.add(auth)
    db.session.commit()
    add_ua_user(ua, user)
    return create_token(user)

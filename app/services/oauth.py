import base64
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime

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


def get_auth_servie(auth_name: str) -> str:
    """Получить ссылку в сервис authorize"""
    if auth_name == "yandex":
        parametrs_url = config.YANDEX_OAUTH
        if auth_name == "vk":
            parametrs_url = config.VK_OAUTH
    url = f'https://oauth.{parametrs_url["url"]}.ru/authorize?' \
          f'response_type={parametrs_url["token"]}' \
          f'&client_id={parametrs_url["client_id"]}' \
          f'&redirect_uri={parametrs_url["redirect_uri"]}' \
          f'&display={parametrs_url["popup"]}' \
          f'{parametrs_url["dop_param"]}'
    return url


class OAuth(ABC):
    """Базовый класс дял OAuth"""
    @abstractmethod
    def get_token_service(self, code):
        pass

    @abstractmethod
    def get_data_service(self, token, ua):
        pass

    def __set_user_service(self, ua, email, age, token):
        user = User.query.filter_by(email=email).first()
        if user is None:
            user = User(email=email, password=uuid.uuid4().hex, age=age)
            db.session.add(user)
            db.session.commit()
            user = User.query.filter_by(email=email).first()
        auth = Auth2(token, user.id)
        db.session.add(auth)
        db.session.commit()
        add_ua_user(ua, user)
        return create_token(user)


class Yandex(OAuth):
    """OAuth Яндекс"""

    def get_token_service(self, code: str):
        """Получить токен сервиса Яндекс"""
        url = 'https://oauth.yandex.ru'
        authorization = base64.b64encode(bytes(f'{config.CLIENT_ID}:{config.CLIENT_SECRET}', 'utf-8'))
        headers = {'Authorization': ("Basic " + authorization.decode("utf-8"))}
        response = requests.post(url=url, headers=headers, data={'grant_type': 'authorization_code', 'code': code}).json
        return response['access_token']

    def get_data_service(self, token: str, ua: str) -> None:
        """Получить данные с сервиса Яндекс"""
        url = 'https://login.yandex.ru/info'
        headers = {'Authorization': f'OAuth {token}'}
        response = requests.options(url=url, headers=headers).json()
        email = response['default_email']
        birthday = response['birthday']
        year_birthday = datetime.strptime(birthday, '%Y-%d-%m').year
        age = datetime.now().year - year_birthday
        self.__set_user_service(ua=ua, email=email, token=token, age=age)


class Vk(OAuth):
    """OAuth ВКонтакте"""
    user_id = ''

    def get_token_service(self, url: str) -> str:
        """Получить токен сервиса ВК"""
        access_token = url.split('#')[1].split('&')[0].split('=')[1]
        self.user_id = url.split('#')[1].split('&')[-1].split('=')[1]
        return access_token

    def get_data_service(self, token: str, ua: str):
        """Получить данные из ВК"""
        url = f'https://api.vk.com/method/users.get?user_id={self.user_id}&v=5.131'
        headers = {'Authorization': f'Bear {token}'}
        response = requests.options(url=url, headers=headers).json()["response"]
        email = response['email']
        birthday = response['bdate']
        year_birthday = datetime.strptime(birthday, '%d-%m-%Y').year
        age = datetime.now().year - year_birthday
        self.__set_user_service(ua=ua, email=email, token=token, age=age)

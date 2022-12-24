import logging
import uuid

from flask import Blueprint
from flask_jwt_extended import create_access_token, create_refresh_token
from werkzeug.security import check_password_hash

from api.v1.msg_text import MsgText
from config.config import Config
from db.db import db
from db.jwt_db import jwt_db
from models.db_models import User, UserAgent
from templates.TOTP import totp_check_template

auth = Blueprint('auth', __name__)
log = logging.getLogger(__name__)

# JWT
ACCESS_EXPIRES = Config().JWT_ACCESS_TOKEN_EXPIRES
jwt_blocklist = jwt_db


def login_service(email: str, password: str, ua: str):
    user = User.query.filter_by(email=email).first()
    if user is None:
        return {'msg': MsgText.INCORRECT_LOGIN}
    if not check_password_hash(user.password, password):
        return {'msg': MsgText.INCORRECT_LOGIN}
    add_ua_user(ua, user)
    if user.auth_two_factor:
        return totp_check_template % email
    return create_token(user)


def create_token(user) -> str:
    additional_claims = {"role": [x.name for x in user.role]}
    access_token = create_access_token(identity=user.id, additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=user.id, additional_claims=additional_claims)
    return {"access_token": access_token, "refresh_token": refresh_token}


def refresh_service(id: uuid, ua: str, role: str) -> str:
    """Выдача нового токена"""
    if check_ua_in_user(ua, id):
        return {'Error': MsgText.NOT_ACCSESS}
    return create_token_id(id, role)


def create_token_id(id, role) -> str:
    additional_claims = {'role': role}
    access_token = create_access_token(identity=id, additional_claims=additional_claims)
    refresh_token = create_refresh_token(identity=id, additional_claims=additional_claims)
    return {"access_token": access_token, "refresh_token": refresh_token}


def check_ua_in_user(ua, id):
    if ua not in [x.ua for x in UserAgent.query.filter_by(user_id=id).all()]:
        return True
    return False


def del_ua_in_user(id: uuid, ua: str) -> None:
    """Удалить юзерагент у пользователя"""
    UserAgent.query.filter_by(user_id=id, ua=ua).delete()


def check_user_exist(username):
    """Проверка существования пользователя"""
    if User.query.filter_by(email=username).first() is not None:
        return True
    return False


def signup_service(username, password, password2, ua) -> str:
    """Регистрация пользователя"""
    if password2 != password:
        return {'msg': MsgText.PASSWORDS_NOT_MATCH}
    if check_user_exist(username):
        return {'msg': MsgText.USER_IS_EXIST}

    user = User(email=username, password=password)
    db.session.add(user)
    db.session.commit()
    user = User.query.filter_by(email=username).first()
    add_ua_user(ua, user)
    return create_token(user)


def add_ua_user(ua, user):
    """Добавляем UA к юзеру"""
    user_id = user.id
    if ua not in [x.ua for x in UserAgent.query.filter_by(user_id=user.id).all()]:
        user_agent = UserAgent(ua=ua, user_id=user_id)
        db.session.add(user_agent)
        db.session.commit()

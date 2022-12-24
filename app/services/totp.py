import logging
import uuid

import pyotp
from flask import Blueprint

from api.v1.msg_text import MsgText
from db.db import db
from models.db_models import User, Totp
from services.auth import create_token_id
from templates.TOTP import totp_sync_template

totp = Blueprint('totp', __name__)
log = logging.getLogger(__name__)


def sync_service(user_id: uuid) -> str:
    """Возвращает шаблон"""
    # Генерация секретного ключа, на его основе будут создавать коды
    secret = pyotp.random_base32()
    user = User.query.filter_by(id=user_id).first()
    totp = Totp(secret, user.id, user)
    db.session.add(totp)
    db.session.commit()
    user.two_factor_secrets.append(totp)
    db.session.add(user)
    db.session.commit()
    # Создаём инстанс генератора кодов на основе секрета
    totp = pyotp.TOTP(secret)
    # Ссылка для передачи секретного кода TOTP-приложению.
    provisioning_url = totp.provisioning_uri(name=user_id + '@praktikum.ru', issuer_name='Test Praktikum app')
    tmpl = totp_sync_template % (provisioning_url)
    return tmpl


def sync_check_totp(user_id: uuid, code: str) -> bool:
    """Верифицируем полученный от пользователя код"""
    user = User.query.filter_by(id=user_id).first()
    secret = user.two_factor_secrets
    totp = pyotp.TOTP(secret[-1].two_factor_secrets)
    if not totp.verify(code):
        return False
    user.auth_two_factor = True
    db.session.add(user)
    db.session.commit()
    return True


def check_totp_service(email: str, code: str) -> str:
    """Проверка кода при авторизации и выдача токенов"""
    user = User.query.filter_by(email=email).first()
    secrets = user.two_factor_secrets
    totp = pyotp.TOTP(secrets[-1].two_factor_secrets)
    if not totp.verify(code):
        return {"msg": MsgText.BED_CODE}
    return create_token_id(user.id, user.role)

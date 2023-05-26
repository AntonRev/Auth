import logging
import uuid

from flask import Blueprint

from db.jwt_db import jwt_db
from models.db_models import User, UserAgent
from models.swagger_schema import UserSchema, UserAgentShema

user = Blueprint('user', __name__)
log = logging.getLogger(__name__)

# Config
ACCESS_EXPIRES = 120

# JWT
jwt_blocklist = jwt_db


def users_service() -> UserSchema:
    users_schema = UserSchema(many=True, only=('id', 'login', 'email'))
    users = User.query.all()
    return users_schema(many=True).dump(users)


def index_service(id: uuid) -> UserSchema:
    user_schema = UserSchema(only=("id", "login", "email", "role", 'auth_two_factor'))
    user = User.query.filter_by(user_id=id).first()
    return user_schema().dump(user)


def history_service(id: uuid, page: str, per_page: str):
    """Получить историю входов"""
    history = UserAgent.query.filter_by(user_id=id).paginate(page=int(page),
                                                            per_page=int(per_page),
                                                            error_out=False).items
    return UserAgentShema(many=True).dump(history)

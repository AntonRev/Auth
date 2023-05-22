import logging
import uuid

from flask import Blueprint

from db.jwt_db import jwt_db
from models.db_models import User, UserAgent
from models.schema import UserSchema, UserAgentShema

user = Blueprint('user', __name__)
log = logging.getLogger(__name__)

# Config
ACCESS_EXPIRES = 120

# JWT
jwt_blocklist = jwt_db


def users_service() -> UserSchema:
    users_schema = UserSchema(many=True, only=('id', 'login', 'email'))
    users = User.query.all()
    us_all = users_schema.dump(users)
    return us_all


def index_service(id: uuid) -> UserSchema:
    user_schema = UserSchema(only=("id", "login", "email", "role", 'auth_two_factor'))
    user = User.query.filter_by(user_id=id).first()
    user_out = user_schema.dump(user)
    return user_out


def history_service(id: uuid, page: str, per_page: str):
    """Получить историю входов"""
    history = UserAgentShema(many=True)
    histor = UserAgent.query.filter_by(user_id=id).paginate(page=int(page),
                                                            per_page=int(per_page),
                                                            error_out=False).items
    history_out = history.dump(histor)
    return history_out

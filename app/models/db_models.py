import logging
import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID
from werkzeug.security import generate_password_hash

from db.db import db

log = logging.getLogger(__name__)


class UserAgent(db.Model):
    __tablename__ = 'ua'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'))
    ua = db.Column(db.String(250))
    user = db.relationship('User', backref="ua")
    data = db.Column(db.DateTime, index=True, default=datetime.utcnow())

    def __init__(self, ua, user_id):
        self.ua = ua
        self.user_id = user_id


class Role(db.Model):
    __tablename__ = "role"
    id = db.Column(UUID(as_uuid=True), default=uuid.uuid4, primary_key=True, unique=True, nullable=False)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))
    permission = db.relationship("Permission")

    def __init__(self, name, description):
        self.name = name
        self.description = description
        log.info('Role created %s' % name)


class RoleUser(db.Model):
    __tablename__ = "role_user"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey("role.id"), primary_key=True)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), primary_key=True)


class Permission(db.Model):
    __tablename__ = "permission"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(80))
    description = db.Column(db.String(255))
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey('role.id'))

    def __init__(self, name, description, role_id):
        self.name = name
        self.description = description
        self.role_id = role_id


class UserPermissions(db.Model):
    __tablename__ = "user_permissions"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    permission_id = db.Column(UUID(as_uuid=True), db.ForeignKey("permission.id"), primary_key=True)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), primary_key=True)


class ReqPermissions(db.Model):
    __tablename__ = "req_permissions"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    permission_id = db.Column(UUID(as_uuid=True), db.ForeignKey("permission.id"), primary_key=True)
    req_id = db.Column(UUID(as_uuid=True), db.ForeignKey("requare.id"), primary_key=True)


class Require(db.Model):
    __tablename__ = "requare"
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(80))
    description = db.Column(db.String(255))
    permission = db.relationship('Permission', secondary='req_permissions')

    def __init__(self, name, description):
        self.name = name
        self.description = description


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    login = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    data_create = db.Column(db.DateTime, index=True, default=datetime.utcnow())
    auth_two_factor = db.Column(db.Boolean, unique=False, default=False)
    age = db.Column(db.Int, index=True, default=18)
    role = db.relationship('Role', secondary='role_user')
    permission = db.relationship('Permission', secondary='user_permissions')

    def __repr__(self):
        return f'<User {self.login}>'

    def __init__(self, email, password, role='user', age=18):
        self.email = email
        self.login = email.split('@')[0]
        self.password = generate_password_hash(password)
        self.registered_on = datetime.now()
        self.role = [Role.query.filter_by(name=role).first()]
        self.age = age


class Totp(db.Model):
    __tablename__ = 'totp'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    two_factor_secrets = db.Column(db.String, unique=True, nullable=True)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), primary_key=True)
    user = db.relationship('User', backref="two_factor_secrets")

    def __init__(self, two_factor_secrets, user_id, user):
        self.user = user
        self.two_factor_secrets = two_factor_secrets
        self.user_id = user_id


class Auth2(db.Model):
    __tablename__ = 'auth'
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'))
    auth_token = db.Column(db.String(250))
    user = db.relationship('User', backref="auth")

    def __init__(self, token, user_id):
        self.auth_token = token
        self.user_id = user_id

import logging
import uuid
from datetime import datetime

from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from werkzeug.security import generate_password_hash

from db.db import db

log = logging.getLogger(__name__)


def create_partition(target, connection, **kw) -> None:
    """ creating partition by user_sign_in """
    connection.execute(
        """CREATE TABLE IF NOT EXISTS "user_hash_1" PARTITION OF "user" FOR VALUES WITH (MODULUS 3, REMAINDER 0)"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS "user_hash_2" PARTITION OF "user" FOR VALUES WITH (MODULUS 3, REMAINDER 1)"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS "user_hash_3" PARTITION OF "user" FOR VALUES WITH (MODULUS 3, REMAINDER 2)"""
    )


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
    permission = db.relationship("Permission", cascade="delete, merge, save-update")

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
    permission = db.relationship('Permission', secondary='req_permissions', cascade="delete, merge, save-update")

    def __init__(self, name, description):
        self.name = name
        self.description = description


class User(db.Model):
    __tablename__ = 'user'
    __table_args__ = (UniqueConstraint('id', 'age_user'),
                      {
                          'postgresql_partition_by': 'HASH (id);',
                          'listeners': [('after_create', create_partition)],
                      }
                      )

    id = db.Column(UUID(as_uuid=True), primary_key=True, unique=True, default=uuid.uuid4, nullable=False)
    login = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    data_create = db.Column(db.DateTime, default=datetime.utcnow())
    auth_two_factor = db.Column(db.Boolean, default=False)
    age_user = db.Column(db.Integer(), primary_key=True)
    role = db.relationship('Role', secondary='role_user', cascade="delete, merge, save-update")
    permission = db.relationship('Permission', secondary='user_permissions', cascade="delete, merge, save-update")

    def __repr__(self):
        return f'<User {self.login}>'

    def __init__(self, email, password, role='user', age_user=18):
        self.email = email
        self.login = email.split('@')[0]
        self.password = generate_password_hash(password)
        self.registered_on = datetime.now()
        self.role = [Role.query.filter_by(name=role).first()]
        self.age_user = age_user


class Totp(db.Model):
    __tablename__ = 'totp'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    two_factor_secrets = db.Column(db.String(80), unique=True, nullable=True)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), primary_key=True)
    user = db.relationship('User', backref="two_factor_secrets", cascade="delete, merge, save-update")

    def __init__(self, two_factor_secrets, user_id, user):
        self.user = user
        self.two_factor_secrets = two_factor_secrets
        self.user_id = user_id


class Auth2(db.Model):
    __tablename__ = 'auth'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('user.id'))
    auth_token = db.Column(db.String(250))
    user = db.relationship('User', backref="auth", cascade="delete, merge, save-update")

    def __init__(self, token, user_id):
        self.auth_token = token
        self.user_id = user_id

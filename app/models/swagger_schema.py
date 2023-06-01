from marshmallow import Schema, fields as f
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from marshmallow_sqlalchemy.fields import fields

from models.db_models import User, Role, Permission, Require, UserAgent


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User

    password = fields.Str()
    email = fields.Email()


class RoleSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Role


class PermissionSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Permission


class RequireShema(SQLAlchemyAutoSchema):
    class Meta:
        model = Require


class TokenSchema(Schema):
    access_token = f.Str()
    refresh_token = f.Str()


class RespSchema(Schema):
    msg = f.Str()


class UserAgentShema(SQLAlchemyAutoSchema):
    class Meta:
        model = UserAgent

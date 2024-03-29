import logging
from datetime import datetime, timedelta, timezone

import click
from flask import Flask, request
from flask_apispec.extension import FlaskApiSpec
from flask_jwt_extended import create_access_token, get_jwt_identity, get_jwt, JWTManager, \
    set_access_cookies
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from opentelemetry import trace
from opentelemetry.instrumentation.flask import FlaskInstrumentor

from api.v1.auth import auth, signup_post, login, logout, refresh
from api.v1.oauth import oauth, get_auth, set_auth
from api.v1.permission import permission, get_permission, get_permissions, change_permission, \
    delete_permission_by_user, set_permission_by_user, get_permission_by_user, create_new_permission
from api.v1.role import rol, get_role, add_role, change_role, delete_role_by_user, get_roles, set_roles_by_user, \
    delete_role
from api.v1.totp import totp, check, sync_check, sync
from api.v1.user import user, users, index
from config.config import config
from config.tracer import configure_tracer
from db.db import init_db, db, init_db_test
from db.jwt_db import jwt_db
from models.db_models import User


def create_app(test=False):
    app = Flask(__name__)
    log = logging.getLogger(__name__)
    ma = Marshmallow(app)

    # Config
    app.config.from_object('config.config.Config')

    # JWT
    jwt = JWTManager(app)
    jwt_blocklist = jwt_db

    if config.ENABLE_TRACER:
        configure_tracer()
        FlaskInstrumentor().instrument_app(app)
        tracer = trace.get_tracer(__name__)

        @app.before_request()
        def before_request():
            request_id = request.headers.get('X-Request-Id')
            if not request_id:
                raise RuntimeError('request id is required')

    # Creat superuser CLI
    @app.cli.command(name="create_user")
    @click.argument("name")
    @click.argument("password")
    def create_user(name, password):
        """Создание супер пользователя из командной строки"""
        with tracer.start_as_current_span('Create super admin'):
            log.info('Creat super user')
            init_db(app)
            u = User(email=name, password=password, role="superadmin")
            db.session.add(u)
            db.session.commit()

    @app.after_request
    def refresh_expiring_jwts(response):
        """Автоматическое обновление токена в cookie после запроса"""
        try:
            exp_timestamp = get_jwt()["exp"]
            now = datetime.now(timezone.utc)
            target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
            if target_timestamp > exp_timestamp:
                access_token = create_access_token(identity=get_jwt_identity())
                set_access_cookies(response, access_token)
            return response
        except (RuntimeError, KeyError):
            # Case where there is not a valid JWT. Just return the original response
            return response

    @jwt.token_in_blocklist_loader
    def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
        jti = jwt_payload["jti"]
        token_in_redis = jwt_blocklist.get(jti)
        return token_in_redis is not None

    # Добавление rout Api
    app.register_blueprint(user, url_prefix='/api/v1/user')
    app.register_blueprint(totp, url_prefix='/api/v1/totp')
    app.register_blueprint(oauth, url_prefix='/api/v1/oauth')
    app.register_blueprint(auth, url_prefix='/api/v1/auth')
    app.register_blueprint(permission, url_prefix='/api/v1/permission')
    app.register_blueprint(rol, url_prefix='/api/v1/role')

    # Добавление документации Swagger
    docs = FlaskApiSpec(app, document_options=False)
    docs.register(signup_post, blueprint='auth')
    docs.register(login, blueprint='auth')
    docs.register(users, blueprint='user')
    docs.register(index, blueprint='user')
    docs.register(logout, blueprint='auth')
    docs.register(refresh, blueprint='auth')
    docs.register(get_permission, blueprint='permission')
    docs.register(change_permission, blueprint='permission')
    docs.register(get_permissions, blueprint='permission')
    docs.register(create_new_permission, blueprint='permission')
    docs.register(get_permission_by_user, blueprint='permission')
    docs.register(set_permission_by_user, blueprint='permission')
    docs.register(delete_permission_by_user, blueprint='permission')
    docs.register(get_role, blueprint='rol')
    docs.register(add_role, blueprint='rol')
    docs.register(change_role, blueprint='rol')
    docs.register(delete_role_by_user, blueprint='rol')
    docs.register(get_roles, blueprint='rol')
    docs.register(set_roles_by_user, blueprint='rol')
    docs.register(delete_role, blueprint='rol')
    docs.register(check, blueprint='totp')
    docs.register(sync_check, blueprint='totp')
    docs.register(sync, blueprint='totp')
    docs.register(get_auth, blueprint='oauth')
    docs.register(set_auth, blueprint='oauth')

    # INITIALIZE
    init_db(app) if not test else init_db_test(app)
    migrate = Migrate(app, db)
    migrate.init_app(app)
    ma.init_app(app)

    return app

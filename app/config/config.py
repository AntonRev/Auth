from datetime import timedelta
from logging import config as logging_config

from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from pydantic import BaseSettings, Field

from config.logger import LOGGING

# Применяем настройки логирования
logging_config.dictConfig(LOGGING)


# Настройки приложения
class Settings(BaseSettings):
    # Настройки Redis
    REDIS_HOST: str = Field('127.0.0.1', env='REDIS_HOST')
    REDIS_PORT: int = Field(6379, env='REDIS_PORT')
    CACHE_EXPIRE_IN_SECONDS: int = Field(300, env='CACHE_EXPIRE_IN_SECONDS')  # 5 минут
    REQUEST_LIMIT_PER_MINUTE: int = Field(500, env='REQUEST_LIMIT_PER_MINUTE')  # 500 запросов в мин с 1 ip при @ratelimit()

    # Настройки Postgresql
    POSTGRES_SERVER: str = Field('127.0.0.1', env='POSTGRES_SERVER')
    POSTGRES_PORT: int = Field(5432, env='POSTGRES_PORT')
    POSTGRES_DB: str = Field('users', env='POSTGRES_DB')
    POSTGRES_USER: str = Field('app', env='POSTGRES_USER')
    POSTGRES_PASSWORD: str = Field('123qwe', env='POSTGRES_PASSWORD')

    # JWT
    JWT_SECRET_KEY: str = Field('super-secret', env='JWT_SECRET_KEY')
    JWT_OPEN_KEY: str = Field('super-secret_open', env='JWT_OPEN_KEY')

    # Jaeger
    HOST_JAEGER: str = Field('localhost', env='HOST_JAEGER')
    PORT_JAEGER: int = Field(6831, env='PORT_JAEGER')
    JAEGER_CONSOLE: bool = Field(False, env='JAEGER_CONSOLE')
    ENABLE_TRACER: bool = Field(False, env='JAEGER_CONSOLE')

    # Yandex Auth
    CLIENT_ID: str = Field('3b33407b90004c1190e163fa373ad942', env='CLIENT_ID')
    CLIENT_SECRET: str = Field('14f0d9e392ae499a9dcdb2c46a3310ea', env='CLIENT_SECRET')
    URL_HOST: str = Field('127.0.0.1', env='FLASK_HOST')
    PORT_HOST: str = Field('5000', env='PORT_HOST')
    YANDEX_OAUTH = {'url': 'yandex',
                    'redirect_uri': 'https://oauth.yandex.ru/verification_code',
                    'client_id': '3b33407b90004c1190e163fa373ad942',
                    'response_type': 'code',
                    'display': 'popup',
                    'dop_oaram': ''}

    # VK Auth
    VK_OAUTH = {'url': 'vk',
                'redirect_uri': 'https://flask/api/v1/oauth/code',
                'client_id': 'client_id',
                'response_type': 'code',
                'display': 'popup',
                'dop_oaram': '&scope=4194304'}


config = Settings()


# Настройки для FLASK
class Config(object):
    DEBUG = True

    # JWT settings
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_SECRET_KEY = config.JWT_SECRET_KEY
    JWT_ALGORITHM = 'HS256'
    OPENAPI_SWAGGER_UI_SUPPORTED_SUBMIT_METHODS = ['get', 'put', 'post', 'delete', 'head', 'patch', 'trace']
    TRAP_HTTP_EXCEPTIONS = 'True'

    # Create an APISpec
    APISPEC_SPEC = APISpec(
        title='Auth Project',
        version='v1',
        plugins=[MarshmallowPlugin()],
        openapi_version='2.0.0'
    )

    APISPEC_SWAGGER_URL = '/api/v1/swagger/'  # URI to access API Doc JSON
    APISPEC_SWAGGER_UI_URL = '/api/v1/swagger-ui/'  # URI to access UI of API Doc
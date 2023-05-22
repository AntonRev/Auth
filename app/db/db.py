import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from config.config import config

db = SQLAlchemy()
log = logging.getLogger(__name__)


def init_db(app: Flask):
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{config.POSTGRES_USER}:{config.POSTGRES_PASSWORD}' \
                                            f'@{config.POSTGRES_SERVER}/{config.POSTGRES_DB}'
    db.init_app(app)
    log.info("init_app")

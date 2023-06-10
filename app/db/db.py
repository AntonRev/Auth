import logging
from flask_migrate import upgrade as flask_migrate_upgrade
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from config.config import config

db = SQLAlchemy()
log = logging.getLogger(__name__)


def init_db(app: Flask):
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{config.POSTGRES_USER}:{config.POSTGRES_PASSWORD}' \
                                            f'@{config.POSTGRES_SERVER}/{config.POSTGRES_DB}'
    db.init_app(app)
    log.info("init_db")

def init_db_test(app: Flask):
    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{config.POSTGRES_USER}:{config.POSTGRES_PASSWORD}' \
                                            f'@{config.POSTGRES_SERVER}/TestDatabase'
    db.init_app(app)
    log.info("init_test_db")
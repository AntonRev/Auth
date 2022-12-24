import pytest as pytest

from app import app
from db.db import db, init_db
from models.db_models import User, Role


@pytest.fixture(scope='session')
def flask_app():
    init_db(app)
    client = app.test_client()
    ctx = app.test_request_context()
    ctx.push()

    yield client

    ctx.pop()


@pytest.fixture(scope='session')
def app_with_data(flask_app):
    role = Role(name='testrole', description='Test user role')
    db.session.add(role)
    db.session.commit()
    user = User(email='testemail', password='tests', role='testrole')
    db.session.add(user)
    db.session.commit()

    yield flask_app

    db.session.delete(user)
    db.session.delete(role)
    db.session.commit()

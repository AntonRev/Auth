import pytest as pytest

from app import app
from db.db import db, init_db
from models.db_models import User, Role

ROLE = 'user'
USER_EMAIL = 'test_email'
USER_PASS = 'test_password'

@pytest.fixture(scope='session')
def flask_app():
    init_db(app)
    with app.test_client() as client:
        ctx = app.test_request_context()
        ctx.push()

        yield client

    ctx.pop()


@pytest.fixture(scope='session')
def app_with_data(flask_app):
    role = Role(name=ROLE, description='Test user role')
    db.session.add(role)
    db.session.commit()
    user = User(email=USER_EMAIL, password=USER_PASS, role=ROLE)
    db.session.add(user)
    db.session.commit()

    yield flask_app

    db.session.delete(user)
    db.session.delete(role)
    db.session.commit()
    db.session.close()

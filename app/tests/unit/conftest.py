import pytest as pytest

from application import create_app
from db.db import db
from models.db_models import User, Role

ROLE = 'user'
USER_EMAIL = 'test_email'
USER_PASS = 'test_password'


@pytest.fixture(scope='session')
def client():
    app = create_app(test=True)
    with app.app_context():
        db.create_all()
        with app.test_client() as client:
            ctx = app.test_request_context()
            ctx.push()
            yield client

        db.session.remove()
        db.drop_all()


@pytest.fixture(scope='session')
def client_with_data(client):
    role = Role(name=ROLE, description='Test user role')
    db.session.add(role)
    db.session.commit()
    user = User(email=USER_EMAIL, password=USER_PASS, role=ROLE)
    db.session.add(user)
    db.session.commit()

    yield client

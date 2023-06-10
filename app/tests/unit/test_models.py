from models.db_models import User
from tests.unit.conftest import ROLE


def test_new_user(client_with_data):
    user = User('patkennedy79@gmail.com', 'FlaskIsAwesome', ROLE)
    assert user.email == 'patkennedy79@gmail.com'
    assert user.password != 'FlaskIsAwesome'
    assert ROLE in [x.name for x in user.role]

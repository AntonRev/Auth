from models.db_models import User


def test_new_user(app_with_data):
    user = User('patkennedy79@gmail.com', 'FlaskIsAwesome', 'tests')
    assert user.email == 'patkennedy79@gmail.com'
    assert user.password != 'FlaskIsAwesome'
    assert 'tests' in [x.name for x in user.role]

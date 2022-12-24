import http

from flask import url_for

access_token = ''
refresh_token = ''
UA = 'werkzeug/2.2.2'


class TestRole:
    def test_auth_no_user(self, flask_app):
        response = flask_app.get(url_for("rol.get_role", role_name='testrole'))
        assert response.status_code == http.HTTPStatus.OK
    def test_add_role(self, flask_app):
        response = flask_app.post(url_for("rol.add_role", role='testrole_3'))
        assert response.status_code == http.HTTPStatus.OK

    def test_change_role(self, flask_app):
        response = flask_app.put(url_for("rol.add_role", role='testrole_3'), json={"description": "test_"})
        assert response.status_code == http.HTTPStatus.OK

    def test_delete_role(self, flask_app):
        response = flask_app.delete(url_for("rol.delete_role", role='testrole_3'))
        assert response.status_code == http.HTTPStatus.OK

    def test_get_roles(self, flask_app):
        response = flask_app.get(url_for("rol.get_roles", user_id='test'))
        assert response.status_code == http.HTTPStatus.OK
    def test_set_roles(self, flask_app):
        response = flask_app.get(url_for("rol.set_roles", user_id='testemail'), json={"role": 'testrole'})
        assert response.status_code == http.HTTPStatus.OK



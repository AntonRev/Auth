import http

import pytest
from flask import url_for

from api.v1.msg_text import MsgText

access_token = ''
refresh_token = ''
UA = 'werkzeug/2.2.2'


class TestAuth:
    def test_auth_no_user(self, flask_app):
        response = flask_app.post(url_for("auth.login"), json={"email": "testemail", "password": "tests"})
        assert response.status_code == http.HTTPStatus.OK

    def test_auth_with_user(self, app_with_data):
        global access_token
        global refresh_token
        response = app_with_data.post(url_for("auth.login"),
                                      json={"email": "testemail", "password": "tests", "role": "testrole"})
        assert response.status_code == http.HTTPStatus.OK
        data = response.json
        assert 'access_token' in data
        assert 'refresh_token' in data
        access_token = data['access_token']
        refresh_token = data['refresh_token']

    def test_refresh_with_user(self, app_with_data):
        global access_token
        global refresh_token
        headers = {'Authorization': f'Bearer {refresh_token}'}
        response = app_with_data.post(url_for("auth.refresh"), headers=headers)
        assert response.status_code == http.HTTPStatus.OK

    def test_logout_with_user(self, app_with_data):
        global access_token
        headers = {'Authorization': f'Bearer {access_token}'}
        response = app_with_data.delete(url_for("auth.logout"), headers=headers)
        assert response.status_code == http.HTTPStatus.OK

    @pytest.mark.parametrize(
        'query_data, expected_answer',
        [
            (
                    {'email': 'email_test', 'password1': 'test_1', 'password2': 'test_1'},
                    {'status': http.HTTPStatus.OK, 'msg': 'access_token'}
            ),
            (
                    {'email': 'email_test', 'password1': 'test_1', 'password2': 'test_1'},
                    {'status': http.HTTPStatus.OK, 'msg': MsgText.USER_IS_EXIST}
            ),
            (
                    {'email': 'email_test_1', 'password1': 'test_1', 'password2': 'test_2'},
                    {'status': http.HTTPStatus.OK, 'msg': MsgText.PASSWORDS_NOT_MATCH}
            ),
            (
                    {'email': 'email_test_2', 'password1': 'test_1', 'password2': None},
                    {'status': http.HTTPStatus.OK, 'msg': MsgText.PASSWORDS_NOT_MATCH}
            ),
            (
                    {'email': None, 'password1': 'test_1', 'password2': 'test_2'},
                    {'status': http.HTTPStatus.OK, 'msg': MsgText.PASSWORDS_NOT_MATCH}
            )
        ]
    )
    def test_sing_with_user(self, app_with_data, query_data, expected_answer):
        response = app_with_data.post(url_for("auth.signup_post"),
                                      json={"email": query_data['email'],
                                            "password1": query_data["password1"],
                                            "password2": query_data["password2"]})
        assert response.status_code == expected_answer["status"]
        data = response.json
        assert expected_answer["msg"] in data['msg']
import http

import pytest
from flask import url_for

from api.v1.msg_text import MsgText
from tests.unit.conftest import USER_EMAIL, USER_PASS, ROLE

access_token = ''
refresh_token = ''
UA = 'werkzeug/2.2.2'


class TestAuth:
    def test_auth_no_user(self, client):
        response = client.post(url_for("auth.login"), json={"email": USER_EMAIL, "password": USER_PASS})
        assert response.status_code == http.HTTPStatus.OK

    def test_auth_with_user(self, client_with_data):
        global access_token
        global refresh_token
        response = client_with_data.post(url_for("auth.login"),
                                         json={"email": USER_EMAIL, "password": USER_PASS, "role": ROLE})
        assert response.status_code == http.HTTPStatus.OK
        data = response.json
        assert 'access_token' in data
        assert 'refresh_token' in data
        access_token = data['access_token']
        refresh_token = data['refresh_token']

    def test_refresh_with_user(self, client_with_data):
        global access_token
        global refresh_token
        headers = {'Authorization': f'Bearer {refresh_token}',
                   'User-Agent': UA}
        response = client_with_data.post(url_for("auth.refresh"), headers=headers)
        assert response.status_code == http.HTTPStatus.OK

    def test_logout_with_user(self, client_with_data):
        global access_token
        headers = {'Authorization': f'Bearer {access_token}'}
        response = client_with_data.delete(url_for("auth.logout"), headers=headers)
        assert response.status_code == http.HTTPStatus.OK

    @pytest.mark.parametrize(
        'query_data, expected_answer',
        [
            (
                    {'email': 'email_test', 'password1': 'test_1', 'password2': 'test_1'},
                    {'status': http.HTTPStatus.OK, 'msg': 'access_token'}
            )
        ]
    )
    def test_true_sing_with_user(self, client_with_data, query_data, expected_answer):
        response = client_with_data.post(url_for("auth.signup_post"),
                                         json={"email": query_data['email'],
                                            "password1": query_data["password1"],
                                            "password2": query_data["password2"],
                                            "age": 18})
        assert response.status_code == expected_answer["status"]
        data = response.json
        assert expected_answer["msg"] in data

    @pytest.mark.parametrize(
        'query_data, expected_answer',
        [
            (
                    {'email': 'email_test', 'password1': 'test_1', 'password2': 'test_1'},
                    {'status': http.HTTPStatus.OK, 'msg': f'{MsgText.USER_IS_EXIST}'}
            ),
            (
                    {'email': 'email_test_1', 'password1': 'test_1', 'password2': 'test_2'},
                    {'status': http.HTTPStatus.OK, 'msg': f'{MsgText.PASSWORDS_NOT_MATCH}'}
            ),
            (
                    {'email': 'email_test_2', 'password1': 'test_1', 'password2': None},
                    {'status': http.HTTPStatus.OK, 'msg': f'{MsgText.PASSWORDS_NOT_MATCH}'}
            ),
            (
                    {'email': None, 'password1': 'test_1', 'password2': 'test_2'},
                    {'status': http.HTTPStatus.OK, 'msg': f'{MsgText.PASSWORDS_NOT_MATCH}'}
            )
        ]
    )
    def test_bad_sing_with_user(self, client_with_data, query_data, expected_answer):
        response = client_with_data.post(url_for("auth.signup_post"),
                                         json={"email": query_data['email'],
                                            "password1": query_data["password1"],
                                            "password2": query_data["password2"],
                                            "age": 18})
        assert response.status_code == expected_answer["status"]
        data = response.json
        assert expected_answer["msg"] in data['msg']

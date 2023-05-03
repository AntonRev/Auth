from functools import wraps

from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity

from models.db_models import Permission, Require


def check_roles(roles=list):
    def requared_role(fn):
        @wraps(fn)
        def wrappers(*arg, **kwargs):
            """Проверка на доступ. Нужна роль у юзера"""
            roles.append('superadmin')
            verify_jwt_in_request()
            claim = get_jwt()
            if not claim:
                return jsonify("Error")
            if claim['role'] in roles:
                return fn(*arg, **kwargs)
            return jsonify(Error='Not access')

        return wrappers

    return requared_role


def chek_all_permission(perm):
    def requared_perm(fn):
        @wraps(fn)
        def wrapper(*arg, **kwargs):
            """Проверка на доступ. Нужны все доступы"""
            verify_jwt_in_request()
            id = get_jwt_identity()
            req_perms = Require.query.filter_by(name=perm).all()
            perms_user = Permission.query.filter_by(user_id=id).all()
            for perm_user in perms_user:
                if perm_user not in req_perms:
                    return jsonify(Error='Not access')
            return fn(*arg, **kwargs)

        return wrapper

    return requared_perm


def chek_one_permission(perm):
    """Проверка на доступ. Нужен хотябы 1 доступ"""

    def requared_perm(fn):
        @wraps(fn)
        def wrapper(*arg, **kwargs):
            verify_jwt_in_request()
            id = get_jwt_identity()
            req_perms = Require.query.filter_by(name=perm).all()
            perms_user = Permission.query.filter_by(user_id=id).all()
            for perm_user in perms_user:
                if perm_user in req_perms:
                    return fn(*arg, **kwargs)
            return jsonify(Error='Not access')

        return wrapper

    return requared_perm

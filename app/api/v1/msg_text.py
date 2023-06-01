from enum import Enum


class MsgText(str, Enum):
    """
    Messages returned
    """
    # Error
    ERROR_BD = 'Error to access BD'
    # auth
    INCORRECT_LOGIN = 'Incorrect login or password.'
    ACCESS_TOKEN_REVOKED = "Access token revoked."
    USER_IS_EXIST = 'User is exist.'
    PASSWORDS_NOT_MATCH = "Passwords don't match! Repeat the input."
    NOT_ACCSESS = 'Not accsess'

    # role & permission
    CREATE = 'Create'
    DELETE = 'Delete'
    ADD = 'Add'
    ROLE_NOT_FOUND = 'Role not found'
    REMOVE = 'Remove'
    SUCCESS = 'Success'
    PERMISSIONS_NOT_FOUND = 'Permissions not found'
    ADD_PERMISSION = 'Add permission'
    REMOVE_PERMISSION = 'Remove permission'

    # totp
    BED_CODE = 'Bed code'

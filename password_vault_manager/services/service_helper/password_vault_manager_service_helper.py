from abc import ABC

from rest_framework.status import HTTP_400_BAD_REQUEST

from password_manager.services.base_service import BaseService
from password_manager.validators.email_validator import EmailValidator
from password_manager.validators.name_validator import NameValidator
from password_manager.validators.password_validator import PasswordValidator
from password_manager.validators.username_validator import UsernameValidator


class PasswordVaultManagerServiceHelper(BaseService, ABC):
    def __init__(self):
        super().__init__()

    def set_status_code(self, *args, **kwargs):
        self.status_code = kwargs['status_code']

    def is_valid_parameters(self, params, is_sign_up=True):
        is_valid, message = UsernameValidator().validate(params.get('username'))

        if not is_valid:
            self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
            return is_valid, {"message": message}

        if is_sign_up:
            is_valid, message = NameValidator().validate(params.get('first_name'))

            if not is_valid:
                self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
                return is_valid, {"message": message}

            is_valid, message = NameValidator().validate(params.get('last_name'))

            if not is_valid:
                self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
                return is_valid, {"message": message}

            is_valid, message = EmailValidator().validate(params.get('email'))

            if not is_valid:
                self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
                return is_valid, {"message": message}

        is_valid, message = PasswordValidator().validate(params.get('password'))

        if not is_valid:
            self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
            return is_valid, {"message": message}

        return True, ""
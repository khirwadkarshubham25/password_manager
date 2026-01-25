import copy

import jwt

from cryptography.fernet import Fernet
from mypy_django_plugin.lib.fullnames import OBJECT_DOES_NOT_EXIST
from rest_framework import status

from password_manager import settings
from password_manager.commons.generic_constants import GenericConstants
from password_vault_manager.models import Users
from password_vault_manager.services.service_helper.password_vault_manager_service_helper import \
    PasswordVaultManagerServiceHelper


class LoginService(PasswordVaultManagerServiceHelper):

    def __init__(self):
        super().__init__()


    def get_request_params(self, *args, **kwargs):
        return {
            'email': kwargs.get('data').get('email'),
            'password': kwargs.get('data').get('password')
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)
        is_valid, message = self.is_valid_parameters(params, is_sign_up=False)

        if not is_valid:
            return {"message": message}

        try:
            user = Users.objects.get(email=params.get('email'))

            key = ""
            with open('secret.key', 'rb') as f:
                key = f.read().strip()

            password = Fernet(key).decrypt(user.password.encode()).decode()

            if password != params['password']:
                self.set_status_code(status_code=status.HTTP_401_UNAUTHORIZED)
                return {"message": GenericConstants.INVALID_EMAIL_PASSWORD}

            token_payload = {
                "id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name
            }

            api_token_payload = copy.deepcopy(token_payload)
            api_token_payload["exp"] = self.get_expiry(GenericConstants.API_TOKEN_TYPE)
            api_token = jwt.encode(api_token_payload, settings.SECRET_KEY)

            refresh_token_payload = copy.deepcopy(token_payload)
            refresh_token_payload["exp"] = self.get_expiry(GenericConstants.REFRESH_TOKEN_TYPE)
            refresh_token = jwt.encode(refresh_token_payload, settings.SECRET_KEY)

            return {
                'api_token': api_token,
                'refresh_token': refresh_token,
                'user_info': token_payload,
                'message': GenericConstants.LOGIN_SUCCESS_MESSAGE
            }
        except OBJECT_DOES_NOT_EXIST as e:
            self.set_status_code(status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.USER_NOT_FOUND}

import base64
import hashlib
from datetime import datetime

from cryptography.fernet import Fernet
from rest_framework.status import HTTP_400_BAD_REQUEST

from password_manager import settings
from password_manager.commons.generic_constants import GenericConstants
from password_vault_manager.models import Users
from password_vault_manager.services.service_helper.password_vault_manager_service_helper import \
    PasswordVaultManagerServiceHelper


class CreateMasterPasswordService(PasswordVaultManagerServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        return {
            'username': kwargs.get('data').get('username'),
            'first_name': kwargs.get('data').get('first_name'),
            'last_name': kwargs.get('data').get('last_name'),
            'email': kwargs.get('data').get('email'),
            'password': kwargs.get('data').get('password')
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)
        is_valid, message = self.is_valid_parameters(params)

        if not is_valid:
            return message

        key = ""
        with open('secret.key', 'rb') as f:
            key = f.read().strip()

        params["password"] = (Fernet(key).encrypt(params["password"].encode())).decode()
        params["created_at"] = datetime.now()
        params["updated_at"] = datetime.now()

        try:
            user = Users.objects.filter(email=params["email"]).count()

            if user > 0:
                self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
                return {"message": GenericConstants.USER_EMAIL_EXISTS_ERROR_MESSAGE.format(params["email"])}

            user = Users.objects.filter(username=params["username"]).count()

            if user > 0:
                self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
                return {"message": GenericConstants.USERNAME_EXISTS_ERROR_MESSAGE.format(params["username"])}

            user = Users(**params)
            user.save()

            return {
                "message": GenericConstants.SIGNUP_SUCCESS_MESSAGE
            }
        except Exception as e:
            print(e)
            self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
            return {
                "message": GenericConstants.SIGNUP_ERROR_MESSAGE
            }

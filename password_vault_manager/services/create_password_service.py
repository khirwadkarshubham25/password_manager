from datetime import datetime

from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_vault_manager.models import UserPasswords
from password_vault_manager.services.service_helper.password_vault_manager_service_helper import \
    PasswordVaultManagerServiceHelper
from password_vault_manager.validators.password_validator import PasswordValidator


class CreatePassword(PasswordVaultManagerServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        return {
            'user_id': kwargs.get('data').get('id'),
            'platform': kwargs.get('data').get('platform'),
            'url': kwargs.get('data').get('url'),
            'password': kwargs.get('data').get('password')
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        is_valid, message = PasswordValidator().validate(params.get('password'))

        if not is_valid:
            return {"message": message}

        params["created_at"] = datetime.now()
        params["updated_at"] = datetime.now()

        try:
            user_password = UserPasswords(**params)
            user_password.save()

            return {"message": GenericConstants.CREATE_PASSWORD_SUCCESS_MESSAGE}

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.CREATE_PASSWORD_ERROR_MESSAGE}
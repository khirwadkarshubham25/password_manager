from password_manager.commons.generic_constants import GenericConstants
from password_vault_manager.models import Users, UserPasswords
from password_vault_manager.services.crypto_service import CryptoService
from rest_framework import status

from password_vault_manager.services.service_helper.password_vault_manager_service_helper import \
    PasswordVaultManagerServiceHelper


class UpdatePasswordService(PasswordVaultManagerServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        user_password_id = kwargs.get('data', {}).get('user_password_id', '')
        password = kwargs.get('data', {}).get('password', '')

        return {
            'user_password_id': user_password_id,
            'password': password
        }

    def validate_parameters(self, params):
        if not params.get('user_password_id'):
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return False, {"message": GenericConstants.INVALID_USER_PASSWORD_ID}

        if not params.get('password'):
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return False, {"message": GenericConstants.PASSWORD_MANDATORY_FIELD_ERROR_MESSAGE}

        return True, ""

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        is_valid, validation_response = self.validate_parameters(params)
        if not is_valid:
            return validation_response

        user_password_id = params.get('user_password_id')
        password = params.get('password')

        try:
            user_password = UserPasswords.objects.filter(id=user_password_id).first()

            if not user_password:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {"message": GenericConstants.USER_PASSWORD_NOT_FOUND}

            user = Users.objects.filter(id=user_password.user_id).first()

            if not user:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {"message": GenericConstants.USER_NOT_FOUND}

            encrypted_password = CryptoService.encrypt_password(
                password,
                user.password
            )

            user_password.password = encrypted_password
            user_password.save()

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                "message": GenericConstants.UPDATE_PASSWORD_SUCCESS_MESSAGE
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {
                'message': GenericConstants.UPDATE_PASSWORD_ERROR_MESSAGE
            }
from rest_framework import status

from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants
from password_vault_manager.models import Users
from password_manager.services.crypto_service import CryptoService
from password_vault_manager.services.service_helper.password_vault_manager_service_helper import \
    PasswordVaultManagerServiceHelper


class LoginUserService(PasswordVaultManagerServiceHelper):

    def __init__(self):
        super().__init__()


    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        username = kwargs.get('data').get('username', '').strip()
        password = kwargs.get('data').get('password', '')

        return {
            'username': username,
            'password': password
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)
        is_valid, message = self.is_valid_parameters(params, is_sign_up=False)

        if not is_valid:
            return {"message": message}

        try:
            user = Users.objects.filter(username=params.get("username")).first()

            # Check if user exists
            if not user:
                self.set_status_code(status_code=status.HTTP_401_UNAUTHORIZED)
                return {"message": GenericConstants.USER_NOT_FOUND}

            is_password_valid = CryptoService.verify_master_password(params.get("password"), user.password)
            if not is_password_valid:
                self.set_status_code(status_code=status.HTTP_401_UNAUTHORIZED)
                return {"message": GenericConstants.INVALID_EMAIL_PASSWORD}

            api_payload = {
                'user_id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }

            # Generate both API and refresh tokens
            tokens = Commons.generate_tokens(api_payload)

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                'message': GenericConstants.LOGIN_SUCCESS_MESSAGE,
                'user_id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                **tokens
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {
                'message': GenericConstants.LOGIN_FAILED_MESSAGE
            }
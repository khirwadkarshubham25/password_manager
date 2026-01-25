from password_manager.commons.generic_constants import GenericConstants
from password_vault_manager.models import Users, UserPasswords
from password_vault_manager.services.crypto_service import CryptoService
from rest_framework import status

from password_vault_manager.services.service_helper.password_vault_manager_service_helper import \
    PasswordVaultManagerServiceHelper


class CreatePasswordService(PasswordVaultManagerServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        user_id = kwargs.get('data', {}).get('user_id', '')
        email = kwargs.get('data', {}).get('email', '').strip()
        platform = kwargs.get('data', {}).get('platform', '').strip()
        url = kwargs.get('data', {}).get('url', '').strip()
        password = kwargs.get('data', {}).get('password', '')

        return {
            'user_id': user_id,
            'email': email,
            'platform': platform,
            'url': url,
            'password': password
        }

    def validate_parameters(self, params):
        if not params.get('user_id'):
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return False, {"message": GenericConstants.USER_NOT_FOUND}

        if not params.get('email'):
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return False, {"message": GenericConstants.EMAIL_MANDATORY_FIELD_ERROR_MESSAGE}

        if not params.get('platform'):
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return False, {"message": GenericConstants.PLATFORM_MANDATORY_FIELD_ERROR_MESSAGE}

        if not params.get('url'):
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return False, {"message": GenericConstants.URL_MANDATORY_FIELD_ERROR_MESSAGE}

        if not params.get('password'):
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return False, {"message": GenericConstants.PASSWORD_MANDATORY_FIELD_ERROR_MESSAGE}

        return True, ""

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        is_valid, validation_response = self.validate_parameters(params)
        if not is_valid:
            return validation_response

        user_id = params.get('user_id')
        email = params.get('email')
        platform = params.get('platform')
        url = params.get('url')
        password = params.get('password')

        try:
            user = Users.objects.filter(id=user_id).first()

            if not user:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {"message": GenericConstants.USER_NOT_FOUND}

            existing_password = UserPasswords.objects.filter(
                user_id=user_id,
                platform=platform,
                email=email
            ).first()

            if existing_password:
                self.set_status_code(status_code=status.HTTP_409_CONFLICT)
                return {
                    "message": GenericConstants.PASSWORD_ENTRY_ALREADY_EXISTS_ERROR_MESSAGE
                }

            encrypted_password = CryptoService.encrypt_password(
                password,
                user.password
            )

            new_password_entry = UserPasswords.objects.create(
                user_id=user_id,
                email=email,
                platform=platform,
                url=url,
                password=encrypted_password
            )

            self.set_status_code(status_code=status.HTTP_201_CREATED)
            return {
                "message": GenericConstants.PASSWORD_ENTRY_CREATED_SUCCESS_MESSAGE
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {
                'message': GenericConstants.PASSWORD_ENTRY_CREATED_ERROR_MESSAGE
            }
import traceback

from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.crypto_service import CryptoService
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import Users


class CreateUserService(PasswordAdminManagerServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        username = kwargs.get('data').get('username', '').strip()
        email = kwargs.get('data').get('email', '').strip().lower()
        first_name = kwargs.get('data').get('first_name', '').strip()
        last_name = kwargs.get('data').get('last_name', '').strip()
        password = kwargs.get('data').get('password', '')

        return {
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': password
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)
        is_valid, message = self.is_valid_parameters(params, is_sign_up=True)

        if not is_valid:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return message

        username = params.get('username')
        email = params.get('email')
        first_name = params.get('first_name')
        last_name = params.get('last_name')
        password = params.get('password')

        if Users.objects.filter(username=username).exists():
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.USERNAME_EXISTS_ERROR_MESSAGE.format(username)}

        # Check if email already exists
        if Users.objects.filter(email=email).exists():
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.USER_EMAIL_EXISTS_ERROR_MESSAGE.format(email)}

        try:
            # Hash password using CryptoService
            hashed_password = CryptoService.hash_master_password(password)

            user = Users.objects.create(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=hashed_password
            )

            return {
                "message": GenericConstants.REGISTRATION_SUCCESS_MESSAGE
            }

        except Exception as e:
            traceback.print_exc(e)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE

from rest_framework import status

from accounts.models import Users, Role, UserProfile
from accounts.services.service_helper.accounts_service_helper import AccountsServiceHelper
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.crypto_service import CryptoService


class RegisterUserService(AccountsServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get("data")
        return {
            "email": data.get("email"),
            "first_name": data.get("first_name", ""),
            "last_name": data.get("last_name", ""),
            "password": data.get("password")
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        if Users.objects.filter(email=params.get("email")).exists():
            self.error = True
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.USER_EMAIL_EXISTS_ERROR_MESSAGE}

        hashed_password = CryptoService.hash_master_password(params.get("password"))

        user = Users.objects.create(
            email=params.get("email"),
            first_name=params.get("first_name"),
            last_name=params.get("last_name"),
            password=hashed_password,
            is_active=True
        )

        UserProfile.objects.create(
            user=user,
            role_id=1
        )

        return {
            "message": GenericConstants.REGISTRATION_SUCCESS_MESSAGE
        }
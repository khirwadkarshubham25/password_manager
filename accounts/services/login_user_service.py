import datetime

from rest_framework import status

from accounts.models import Users
from accounts.services.service_helper.accounts_service_helper import AccountsServiceHelper
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.crypto_service import CryptoService


class LoginUserService(AccountsServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get("data")
        return {
            "email": data.get("email"),
            "password": data.get("password")
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        try:
            user = Users.objects.select_related("profile__role").get(email=params.get("email"))
        except Users.DoesNotExist:
            self.error = True
            self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
            return {"message": GenericConstants.USER_NOT_FOUND}

        if not CryptoService.verify_master_password(params.get("password"), user.password):
            self.error = True
            self.set_status_code(status_code=status.HTTP_401_UNAUTHORIZED)
            return {"message": GenericConstants.INVALID_USER_PASSWORD_ID}

        token_payload = {
            "user_id": user.id,
            "email": user.email,
            "role_id": user.profile.role_id
        }

        api_token, refresh_token = self.generate_tokens(token_payload)

        return {
            "message": GenericConstants.LOGIN_SUCCESS_MESSAGE,
            "user_id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role_id": user.profile.role_id,
            "api_token": api_token,
            "refresh_token": refresh_token
        }
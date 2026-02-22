from rest_framework import status

from accounts.models import Users
from accounts.services.service_helper.accounts_service_helper import AccountsServiceHelper
from password_manager.commons.generic_constants import GenericConstants
from password_manager.commons.token_verifier import TokenVerifier


class RefreshTokenService(AccountsServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        refresh_token = kwargs.get('data', {}).get('refresh_token', '').strip()

        return {
            'refresh_token': refresh_token,
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        refresh_token = params.get('refresh_token')

        if not refresh_token:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.REFRESH_TOKEN_MANDATORY_ERROR_MESSAGE}

        try:
            is_valid, result = TokenVerifier.verify_token(refresh_token)

            if not is_valid:
                self.set_status_code(status_code=status.HTTP_401_UNAUTHORIZED)
                return {"message": result}  # result contains error message

            user_id = result.get('user_id')

            if not user_id:
                self.set_status_code(status_code=status.HTTP_401_UNAUTHORIZED)
                return {"message": GenericConstants.TOKEN_USER_ID_NOT_FOUND_ERROR_MESSAGE}

            user = Users.objects.select_related("profile__role").get(id=user_id)

            if not user:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {"message": GenericConstants.USER_NOT_FOUND}

            token_payload = {
                "user_id": user.id,
                "email": user.email,
                "role_id": user.profile.role_id
            }

            api_token, refresh_token = self.generate_tokens(token_payload)
            return {
                'message': GenericConstants.TOKEN_REFRESH_SUCCESS_MESSAGE,
                'api_token': api_token,
                'refresh_token': refresh_token,
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {
                'message': GenericConstants.TOKEN_REFRESH_ERROR_MESSAGE
            }

    def set_status_code(self, *args, **kwargs):
        self.status_code = kwargs['status_code']
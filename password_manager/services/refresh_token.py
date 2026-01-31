from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants
from password_manager.commons.token_verifier import TokenVerifier
from password_manager.services.base_service import BaseService
from rest_framework import status

from password_manager_admin.models import AdminUsers
from password_vault_manager.models import Users


class RefreshTokenService(BaseService):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        refresh_token = kwargs.get('data', {}).get('refresh_token', '').strip()
        is_admin = kwargs.get('data', {}).get('is_admin', False)

        return {
            'refresh_token': refresh_token,
            'is_admin': is_admin
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        refresh_token = params.get('refresh_token')
        is_admin = params.get('is_admin')

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

            if is_admin:
                user = AdminUsers.objects.filter(id=user_id).first()
            else:
                user = Users.objects.filter(id=user_id).first()

            if not user:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {"message": GenericConstants.USER_NOT_FOUND}

            api_payload = {
                'user_id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }

            api_token, api_token_expiry = Commons.generate_jwt_token(
                GenericConstants.API_TOKEN_TYPE,
                api_payload
            )

            refresh_token_new, refresh_token_expiry = Commons.generate_jwt_token(
                GenericConstants.REFRESH_TOKEN_TYPE,
                api_payload
            )

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                'message': GenericConstants.TOKEN_REFRESH_SUCCESS_MESSAGE,
                'api_token': api_token,
                'api_token_expiry': api_token_expiry.isoformat(),
                'refresh_token': refresh_token_new,
                'refresh_token_expiry': refresh_token_expiry.isoformat()
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {
                'message': GenericConstants.TOKEN_REFRESH_ERROR_MESSAGE
            }

    def set_status_code(self, *args, **kwargs):
        self.status_code = kwargs['status_code']
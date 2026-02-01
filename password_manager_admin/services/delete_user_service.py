from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import Users


class DeleteUserService(PasswordAdminManagerServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        user_id = kwargs.get('data', {}).get('user_id', None)

        if user_id:
            return {
                'user_id': int(user_id)
            }

        return {}

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        user_id = params.get('user_id')
        if not user_id:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {'message': 'User ID is required'}

        # Check if user exists
        try:
            user = Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
            return {'message': GenericConstants.INVALID_USER_ID}

        try:
            username = user.username

            user.delete()
            return {
                'message': f'User {username} deleted successfully',
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {'message': GenericConstants.INTERNAL_SERVER_ERROR_MESSAGE}
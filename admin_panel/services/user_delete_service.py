import sys
import traceback

from rest_framework import status

from accounts.models import Users
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class UserDeleteService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        user_id = data.get('user_id')
        admin_user_id = data.get('admin_user_id')
        return {
            'user_id': int(user_id) if user_id else None,
            'admin_user_id': int(admin_user_id) if admin_user_id else None
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        user_id = params.get('user_id')
        admin_user_id = params.get('admin_user_id')

        if not user_id:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {'message': 'User ID is required'}

        try:
            user = Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
            return {'message': GenericConstants.USER_NOT_FOUND}

        try:
            old_values = {"email": user.email, "first_name": user.first_name, "last_name": user.last_name}
            user.delete()

            Commons.create_audit_log(
                user_id=admin_user_id,
                action='delete',
                resource_type='user',
                resource_id=user_id,
                old_values=old_values
            )

            return {
                'message': GenericConstants.USER_DELETE_SUCCESSFUL_MESSAGE
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
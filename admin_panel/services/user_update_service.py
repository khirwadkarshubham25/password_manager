import sys
import traceback

from rest_framework import status

from accounts.models import Users, UserProfile
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class UserUpdateService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        user_id = data.get('user_id')
        admin_user_id = data.get('admin_user_id')

        try:
            user_id = int(user_id) if user_id else None
        except (ValueError, TypeError):
            user_id = None

        return {
            'user_id': user_id,
            'admin_user_id': admin_user_id,
            'email': data.get('email', '').strip().lower(),
            'first_name': data.get('first_name', '').strip(),
            'last_name': data.get('last_name', '').strip(),
            'phone': data.get('phone', '').strip(),
            'address': data.get('address', '').strip(),
            'is_active': data.get('is_active', True),
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        user_id = params.get('user_id')
        admin_user_id = params.get('admin_user_id')

        if not user_id:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {'message': 'User ID is required'}

        try:
            user = Users.objects.select_related('profile').get(id=user_id)
        except Users.DoesNotExist:
            self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
            return {'message': GenericConstants.USER_NOT_FOUND}

        try:
            old_values = {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone': user.profile.phone,
                'address': user.profile.address
            }

            # Update Users fields
            email = params.get('email')
            if email and email != user.email:
                if Users.objects.filter(email=email).exists():
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': GenericConstants.USER_EMAIL_EXISTS_ERROR_MESSAGE}
                user.email = email

            first_name = params.get('first_name')
            if first_name:
                user.first_name = first_name

            last_name = params.get('last_name')
            if last_name:
                user.last_name = last_name

            is_active = params.get('is_active')

            if is_active is not None:
                user.is_active = is_active

            user.save()

            # Update UserProfile fields
            profile = user.profile

            phone = params.get('phone')
            if phone:
                profile.phone = phone

            address = params.get('address')
            if address:
                profile.address = address

            profile.save()

            new_values = {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone': profile.phone,
                'address': profile.address
            }

            Commons.create_audit_log(
                user_id=admin_user_id,
                action='update',
                resource_type='user',
                resource_id=user_id,
                old_values=old_values,
                new_values=new_values
            )

            return {
                'message': GenericConstants.USER_UPDATE_SUCCESSFUL_MESSAGE
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
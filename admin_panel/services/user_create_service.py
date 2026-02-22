import traceback
import sys

from rest_framework import status

from accounts.models import Users, UserProfile
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.crypto_service import CryptoService


class UserCreateService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data')
        return {
            'email': data.get('email', '').strip().lower(),
            'first_name': data.get('first_name', '').strip(),
            'last_name': data.get('last_name', '').strip(),
            'password': data.get('password', ''),
            'role_id': data.get('role_id'),
            'user_id': data.get('admin_user_id')
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        is_valid, message = self.is_valid_parameters(
            params,
            required_fields=['email', 'password', 'role_id']
        )
        if not is_valid:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return message

        email = params.get('email')
        first_name = params.get('first_name')
        last_name = params.get('last_name')
        password = params.get('password')
        role_id = params.get('role_id')

        if Users.objects.filter(email=email).exists():
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.USER_EMAIL_EXISTS_ERROR_MESSAGE}

        try:
            hashed_password = CryptoService.hash_master_password(password)

            user = Users.objects.create(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=hashed_password
            )

            UserProfile.objects.create(
                user=user,
                role_id=role_id
            )

            Commons.create_audit_log(
                user_id=params.get("user_id"),
                action='create',
                resource_type='user',
                resource_id=user.id,
                new_values={"email": email, "first_name": first_name, "last_name": last_name, "role_id": role_id}
            )

            return {
                "message": GenericConstants.REGISTRATION_SUCCESS_MESSAGE
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
from rest_framework import status

from accounts.models import Role
from accounts.services.service_helper.accounts_service_helper import AccountsServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class RoleUpdateService(AccountsServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get("data")
        return {
            "role_id": data.get("role_id"),
            "name": data.get("name"),
            "description": data.get("description", "")
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        try:
            role = Role.objects.get(id=params.get("role_id"))
        except Role.DoesNotExist:
            self.error = True
            self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
            return {"message": GenericConstants.ROLE_NOT_FOUND_MESSAGE}

        role.name = params.get("name")
        role.description = params.get("description")
        role.save()

        Commons.create_audit_log(user_id=1, action='update', resource_type='role', resource_id=role.id)

        return {
            "message": GenericConstants.ROLE_UPDATE_SUCCESSFUL_MESSAGE
        }
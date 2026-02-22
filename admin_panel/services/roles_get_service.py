from accounts.models import Role
from accounts.services.service_helper.accounts_service_helper import AccountsServiceHelper


class RolesGetService(AccountsServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        pass

    def get_data(self, *args, **kwargs):

        roles = Role.objects.all()

        return {
            "roles": [
                {
                    "id": role.id,
                    "name": role.name,
                    "description": role.description,
                    "created_at": role.created_at.isoformat()
                }
                for role in roles
            ]
        }
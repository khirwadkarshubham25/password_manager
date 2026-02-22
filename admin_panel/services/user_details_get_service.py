from rest_framework import status

from accounts.models import Users, UserProfile
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class UserDetailsGetService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get("data")
        return {
            "user_id": int(data.get("user_id"))
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        try:
            user = Users.objects.select_related('profile__role').get(id=params.get("user_id"))
            user_profile = UserProfile.objects.get(user=user)
        except (Users.DoesNotExist, UserProfile.DoesNotExist):
            self.error = True
            self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
            return {"message": GenericConstants.USER_NOT_FOUND}

        return {
            "data": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat(),
                "role_name": user_profile.role.name,
                "phone": user_profile.phone,
                "address": user_profile.address,
                "is_verified": user_profile.is_verified
            }
        }
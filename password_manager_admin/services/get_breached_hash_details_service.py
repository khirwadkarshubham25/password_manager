from rest_framework import status
from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import PasswordAdminManagerServiceHelper
from password_manager_admin.models import BreachedPasswordHash

class GetBreachedHashDetailsService(PasswordAdminManagerServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        hash_id = kwargs.get('data', {}).get('hash_id', '').strip()
        return {'hash_id': hash_id}

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)
            if not params['hash_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Hash ID required'}
            try:
                h = BreachedPasswordHash.objects.get(id=int(params['hash_id']))
                self.set_status_code(status_code=status.HTTP_200_OK)
                return {'message': 'Success', 'data': {'id': h.id}}
            except (ValueError, BreachedPasswordHash.DoesNotExist):
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': 'Not found'}
        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
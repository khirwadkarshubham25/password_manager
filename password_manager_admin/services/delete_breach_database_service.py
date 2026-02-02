from rest_framework import status
from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import PasswordAdminManagerServiceHelper
from password_manager_admin.models import BreachDatabase

class DeleteBreachDatabaseService(PasswordAdminManagerServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        database_id = kwargs.get('data', {}).get('breach_database_id', '')
        return {'database_id': database_id}

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)
            if not params['database_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Database ID required'}
            try:
                db = BreachDatabase.objects.get(id=int(params['database_id']))
                db.delete()
                self.set_status_code(status_code=status.HTTP_200_OK)
                return {'message': 'Deleted', 'deleted_id': int(params['database_id'])}
            except (ValueError, BreachDatabase.DoesNotExist):
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': 'Not found'}
        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {'message': GenericConstants.INTERNAL_SERVER_ERROR_MESSAGE}
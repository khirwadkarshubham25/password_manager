import sys
import traceback

from rest_framework import status

from admin_panel.models import BreachDatabase
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class BreachDatabaseDeleteService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'breach_database_id': data.get('breach_database_id', ''),
            'user_id': data.get('admin_user_id')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)
            breach_database_id = params.get('breach_database_id')

            if not breach_database_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Breach database ID is required'}

            try:
                breach_database_id = int(breach_database_id)
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid breach database ID. Must be numeric'}

            try:
                breach_database = BreachDatabase.objects.get(id=breach_database_id)
            except BreachDatabase.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.BREACH_DATABASE_NOT_FOUND_MESSAGE}

            old_values = {
                'source_name': breach_database.source_name,
                'source_url': breach_database.source_url,
                'status': breach_database.status
            }

            breach_database.delete()

            Commons.create_audit_log(
                user_id=params.get('user_id'),
                action='delete',
                resource_type='breach_database',
                resource_id=breach_database_id,
                old_values=old_values
            )

            return {'message': GenericConstants.BREACH_DATABASE_DELETE_SUCCESSFUL_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
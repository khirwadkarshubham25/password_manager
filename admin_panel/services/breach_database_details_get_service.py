import sys
import traceback

from rest_framework import status

from admin_panel.models import BreachDatabase
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class BreachDatabaseDetailsGetService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'breach_database_id': data.get('breach_database_id', '').strip()
        }

    def _validate_database_id(self, database_id):
        if not database_id:
            return False, None, 'Breach database ID is required'
        try:
            return True, int(database_id), None
        except (ValueError, TypeError):
            return False, None, 'Invalid breach database ID. Must be numeric'

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, database_id, error_msg = self._validate_database_id(params['breach_database_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            try:
                breach_database = BreachDatabase.objects.get(id=database_id)
            except BreachDatabase.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.BREACH_DATABASE_NOT_FOUND_MESSAGE}

            return {
                'data': {
                    'breach_database_id': breach_database.id,
                    'source_name': breach_database.source_name,
                    'source_url': breach_database.source_url,
                    'authentication_method': breach_database.authentication_method,
                    'hash_format': breach_database.hash_format,
                    'description': breach_database.description,
                    'api_key': breach_database.api_key,
                    'status': breach_database.status,
                    'last_updated': breach_database.last_updated.isoformat() if breach_database.last_updated else None,
                    'next_update_scheduled': breach_database.next_update_scheduled.isoformat() if breach_database.next_update_scheduled else None,
                    'created_at': breach_database.created_at.isoformat(),
                    'updated_at': breach_database.updated_at.isoformat()
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
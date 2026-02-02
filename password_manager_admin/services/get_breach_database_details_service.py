from rest_framework import status
from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import BreachDatabase


class GetBreachDatabaseDetailsService(PasswordAdminManagerServiceHelper):
    """Service for retrieving breach database details"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})
        breach_database_id = data.get('breach_database_id', '').strip()
        return {'breach_database_id': breach_database_id}

    def _validate_database_id(self, database_id):
        """Validate database ID format"""
        if not database_id:
            return False, None, 'Database ID is required'

        try:
            database_id_int = int(database_id)
            return True, database_id_int, None
        except (ValueError, TypeError):
            return False, None, 'Invalid Database ID format. Must be numeric'

    def get_data(self, *args, **kwargs):
        """Retrieve breach database details"""
        try:
            params = self.get_request_params(*args, **kwargs)
            print(params)
            # Validate database_id
            is_valid, database_id, error_msg = self._validate_database_id(params['breach_database_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Fetch database details
            try:
                breach_database = BreachDatabase.objects.get(id=database_id)
            except BreachDatabase.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Breach database with ID {database_id} not found'}

            # Build response data
            data = {
                'breach_database_id': breach_database.id,
                'source_name': breach_database.source_name,
                'source_url': breach_database.source_url,
                'total_hashes': breach_database.total_hashes,
                'last_updated': breach_database.last_updated.isoformat() if breach_database.last_updated else None,
                'next_update_scheduled': breach_database.next_update_scheduled.isoformat() if breach_database.next_update_scheduled else None,
                'api_key': breach_database.api_key,
                'authentication_method': breach_database.authentication_method,
                'hash_format': breach_database.hash_format,
                'description': breach_database.description,
                'data_storage_path': breach_database.data_storage_path,
                'is_active': True if breach_database.status == 1 else False,
                'created_at': breach_database.created_at.isoformat() if breach_database.created_at else None,
                'updated_at': breach_database.updated_at.isoformat() if breach_database.updated_at else None
            }

            return {
                'data': data
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
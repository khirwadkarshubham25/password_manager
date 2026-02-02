from datetime import datetime

from django.db import transaction
from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import BreachDatabase


class UpdateBreachDatabaseService(PasswordAdminManagerServiceHelper):
    """Service for updating breach database sources"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})

        return {
            'breach_database_id': data.get('breach_database_id'),
            'source_name': data.get('source_name'),
            'source_url': data.get('source_url'),
            'total_hashes': data.get('total_hashes'),
            'last_updated': data.get('last_updated'),
            'next_update_scheduled': data.get('next_update_scheduled'),
            'api_key': data.get('api_key'),
            'authentication_method': data.get('authentication_method'),
            'hash_format': data.get('hash_format'),
            'description': data.get('description'),
            'data_storage_path': data.get('data_storage_path'),
            'is_active': data.get('is_active'),
        }

    def _validate_database_id(self, database_id):
        """Validate database ID format"""
        if not database_id:
            return False, None, 'Database ID is required'

        try:
            database_id_int = int(database_id)
            return True, database_id_int, None
        except (ValueError, TypeError):
            return False, None, 'Invalid Database ID format. Must be numeric'

    def _validate_authentication_method(self, auth_method):
        """Validate authentication method"""
        if auth_method:
            valid_methods = ['NONE', 'API_KEY', 'OAUTH', 'BASIC']
            if auth_method not in valid_methods:
                return False, f'Invalid authentication method. Must be one of: {", ".join(valid_methods)}'
        return True, None

    def _validate_hash_format(self, hash_format):
        """Validate hash format"""
        if hash_format:
            valid_formats = ['SHA1', 'SHA256', 'MD5']
            if hash_format not in valid_formats:
                return False, f'Invalid hash format. Must be one of: {", ".join(valid_formats)}'
        return True, None

    def _validate_total_hashes(self, total_hashes):
        """Validate total_hashes is a valid integer"""
        if total_hashes is not None:
            try:
                total_hashes_int = int(total_hashes)
                if total_hashes_int < 0:
                    return False, None, 'Total hashes must be a positive number'
                return True, total_hashes_int, None
            except (ValueError, TypeError):
                return False, None, 'Total hashes must be a valid number'
        return True, None, None

    def _validate_is_active(self, is_active_value):
        """Validate is_active field"""
        if is_active_value is not None:
            if not isinstance(is_active_value, bool):
                return False, 'Invalid is_active value. Must be boolean (true/false)'
        return True, None

    def _check_duplicate_source_name(self, breach_database, source_name):
        """Check if update would create duplicate source name"""
        if source_name and source_name != breach_database.source_name:
            duplicate = BreachDatabase.objects.filter(source_name=source_name).exclude(id=breach_database.id).exists()
            return not duplicate, f'Breach database with source name "{source_name}" already exists'
        return True, None

    def get_data(self, *args, **kwargs):
        """Update breach database source"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Validate database_id
            is_valid, database_id, error_msg = self._validate_database_id(params['breach_database_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Check if breach database exists
            try:
                breach_database = BreachDatabase.objects.get(id=database_id)
            except BreachDatabase.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Breach database with ID {database_id} not found'}

            # Track if any field is being updated
            has_updates = False

            # Validate authentication method
            is_valid, error_msg = self._validate_authentication_method(params['authentication_method'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Validate hash format
            is_valid, error_msg = self._validate_hash_format(params['hash_format'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Validate total_hashes
            is_valid, total_hashes, error_msg = self._validate_total_hashes(params['total_hashes'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Validate is_active
            is_valid, error_msg = self._validate_is_active(params.get('is_active'))
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Check for duplicate source name
            is_valid, error_msg = self._check_duplicate_source_name(breach_database, params['source_name'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Check if at least one field is being updated
            if (not params['source_name'] and
                not params['source_url'] and
                params['total_hashes'] is None and
                not params['last_updated'] and
                not params['next_update_scheduled'] and
                params['api_key'] is None and
                not params['authentication_method'] and
                not params['hash_format'] and
                params['description'] is None and
                params['data_storage_path'] is None and
                params['is_active'] is None):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'No fields to update. Provide at least one field to update'}

            # Update breach database within transaction
            with transaction.atomic():
                if params['source_name']:
                    breach_database.source_name = params['source_name']
                    has_updates = True

                if params['source_url']:
                    breach_database.source_url = params['source_url']
                    has_updates = True

                if params['total_hashes'] is not None:
                    breach_database.total_hashes = total_hashes
                    has_updates = True

                if params['last_updated']:
                    breach_database.last_updated = params['last_updated']
                    has_updates = True

                if params['next_update_scheduled']:
                    breach_database.next_update_scheduled = params['next_update_scheduled']
                    has_updates = True

                if params['api_key'] is not None:
                    breach_database.api_key = params['api_key']
                    has_updates = True

                if params['authentication_method']:
                    breach_database.authentication_method = params['authentication_method']
                    has_updates = True

                if params['hash_format']:
                    breach_database.hash_format = params['hash_format']
                    has_updates = True

                if params['description'] is not None:
                    breach_database.description = params['description']
                    has_updates = True

                if params['data_storage_path'] is not None:
                    breach_database.data_storage_path = params['data_storage_path']
                    has_updates = True

                if params['is_active'] is not None:
                    breach_database.status = 1 if params['is_active'] else 0
                    has_updates = True

                breach_database.save()

            # Return updated breach database details
            return {
                'message': 'Breach database updated successfully'
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {'message': GenericConstants.ERROR_MESSAGE}
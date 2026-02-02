from datetime import datetime

from django.db import transaction
from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import BreachDatabase


class CreateBreachDatabaseService(PasswordAdminManagerServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})

        return {
            'source_name': data.get('source_name'),
            'source_url': data.get('source_url'),
            'total_hashes': data.get('total_hashes', 0),
            'api_key': data.get('api_key'),
            'authentication_method': data.get('authentication_method', 'NONE'),
            'hash_format': data.get('hash_format', 'SHA1'),
            'description': data.get('description', ''),
            'data_storage_path': data.get('data_storage_path'),
        }

    def _validate_required_fields(self, params):
        """Validate required fields"""
        if not params['source_name']:
            return False, 'Source name is required'

        if not params['source_url']:
            return False, 'Source URL is required'

        return True, None

    def _validate_authentication_method(self, auth_method):
        """Validate authentication method"""
        valid_methods = ['NONE', 'API_KEY', 'OAUTH', 'BASIC']
        if auth_method not in valid_methods:
            return False, f'Invalid authentication method. Must be one of: {", ".join(valid_methods)}'
        return True, None

    def _validate_hash_format(self, hash_format):
        """Validate hash format"""
        valid_formats = ['SHA1', 'SHA256', 'MD5']
        if hash_format not in valid_formats:
            return False, f'Invalid hash format. Must be one of: {", ".join(valid_formats)}'
        return True, None

    def _validate_total_hashes(self, total_hashes):
        """Validate total_hashes is a valid integer"""
        try:
            total_hashes_int = int(total_hashes)
            if total_hashes_int < 0:
                return False, None, 'Total hashes must be a positive number'
            return True, total_hashes_int, None
        except (ValueError, TypeError):
            return False, None, 'Total hashes must be a valid number'

    def get_data(self, *args, **kwargs):
        """Create new breach database source"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Validate required fields
            is_valid, error_msg = self._validate_required_fields(params)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

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

            # Check for duplicate source name
            if BreachDatabase.objects.filter(source_name=params['source_name']).exists():
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': f'Breach database with source name "{params["source_name"]}" already exists'}

            # Create breach database within a transaction
            with transaction.atomic():
                breach_database = BreachDatabase.objects.create(
                    source_name=params['source_name'],
                    source_url=params['source_url'],
                    total_hashes=total_hashes,
                    api_key=params['api_key'],
                    authentication_method=params['authentication_method'],
                    hash_format=params['hash_format'],
                    description=params['description'],
                    data_storage_path=params['data_storage_path'],
                    status=1  # Active by default
                )

            # Return breach database details
            return {
                'message': 'Breach database created successfully',
                'data': {
                    'breach_database_id': breach_database.id,
                    'source_name': breach_database.source_name,
                    'source_url': breach_database.source_url,
                    'total_hashes': breach_database.total_hashes,
                    'authentication_method': breach_database.authentication_method,
                    'hash_format': breach_database.hash_format,
                    'is_active': True if breach_database.status == 1 else False,
                    'created_at': breach_database.created_at.isoformat() if breach_database.created_at else None
                }
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
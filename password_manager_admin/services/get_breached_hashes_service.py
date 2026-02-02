import traceback

from rest_framework import status
from password_manager.commons.generic_constants import GenericConstants
from password_manager.validators.page_validator import PageValidator
from password_manager.validators.sort_validator import SortValidator
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import BreachedPasswordHash


class GetBreachedHashesService(PasswordAdminManagerServiceHelper):
    """Service for retrieving breached password hashes"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})
        return {
            'page': data.get('page', '1').strip(),
            'page_size': data.get('page_size', '10').strip(),
            'sort_by': data.get('sort_by', 'password_hash').strip(),
            'sort_order': data.get('sort_order', 'desc').strip().lower(),
            'severity': data.get('severity', '').strip(),
            'breach_database_id': data.get('breach_database_id', '')
        }

    def _validate_severity(self, severity):
        """Validate severity filter"""
        if severity:
            valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            if severity.upper() not in valid_severities:
                return False, f'Invalid severity. Must be one of: {", ".join(valid_severities)}'
        return True, None

    def _validate_breach_source_id(self, breach_source_id):
        """Validate breach_source_id is numeric"""
        if breach_source_id:
            try:
                int(breach_source_id)
                return True, None
            except (ValueError, TypeError):
                return False, 'Invalid breach_source_id. Must be numeric'
        return True, None

    def get_data(self, *args, **kwargs):
        """Retrieve breached hashes with pagination, sorting, and filtering"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Validate pagination
            is_valid, message = PageValidator().validate_pagination_params(
                params['page'],
                params['page_size']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Validate sorting
            allowed_sort_fields = [
                'password_hash',
                'hash_format',
                'breach_source_name'  # For sorting by breach source name
            ]
            is_valid, message = SortValidator().validate_sort_params(
                allowed_sort_fields,
                params['sort_by'],
                params['sort_order']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Validate severity filter
            is_valid, message = self._validate_severity(params['severity'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Validate breach_source_id
            is_valid, message = self._validate_breach_source_id(params['breach_database_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Build query with select_related for foreign key
            query = BreachedPasswordHash.objects.select_related('breach_database').all()

            # Apply filters
            if params['severity']:
                query = query.filter(severity=params['severity'].upper())

            if params['breach_database_id']:
                query = query.filter(breach_database_id=int(params['breach_database_id']))

            # Get total count before pagination
            total_count = query.count()

            # Apply sorting
            sort_field = f"-{params['sort_by']}" if params['sort_order'] == 'desc' else params['sort_by']
            query = query.order_by(sort_field)
            page = int(params['page'])
            page_size = int(params['page_size'])
            # Apply pagination
            start_index = (page - 1) * page_size
            hashes = query[start_index:start_index + page_size]

            # Build response data - minimal fields for list view
            hashes_data = [
                {
                    'breach_hash_id': hash_obj.id,
                    'password_hash': hash_obj.password_hash,
                    'hash_format': hash_obj.hash_format,
                    'breach_database_id': hash_obj.breach_database_id,
                    'breach_source_name': hash_obj.breach_database.source_name
                }
                for hash_obj in hashes
            ]

            # Calculate total pages
            total_pages = (total_count + page_size - 1) // page_size

            return {
                'data': hashes_data,
                'pagination': {
                    'total': total_count,
                    'page': page,
                    'page_size': page_size,
                    'total_pages': total_pages
                },
                'sorting': {
                    'sort_by': params['sort_by'],
                    'sort_order': params['sort_order']
                },
                'filters': {
                    'severity': params['severity'],
                    'breach_database_id': params['breach_database_id']
                }
            }

        except Exception as e:
            traceback.print_exc(e)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {'message': GenericConstants.ERROR_MESSAGE}
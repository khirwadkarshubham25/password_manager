import traceback

from rest_framework import status
from password_manager.commons.generic_constants import GenericConstants
from password_manager.validators.page_validator import PageValidator
from password_manager.validators.sort_validator import SortValidator
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import BreachDatabase


class GetBreachDatabasesService(PasswordAdminManagerServiceHelper):
    """Service for retrieving breach databases"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})
        return {
            'page': data.get('page', '1').strip(),
            'page_size': data.get('page_size', '10').strip(),
            'sort_by': data.get('sort_by', 'created_at').strip(),
            'sort_order': data.get('sort_order', 'desc').strip().lower()
        }

    def get_data(self, *args, **kwargs):
        """Retrieve breach databases with pagination and sorting"""
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
                'source_name',
                'source_url',
                'total_hashes'
            ]
            is_valid, message = SortValidator().validate_sort_params(
                allowed_sort_fields,
                params['sort_by'],
                params['sort_order']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            page = int(params.get('page', '1').strip())
            page_size = int(params.get('page_size', '1').strip())
            # Build query
            query = BreachDatabase.objects.all()
            total_count = query.count()

            # Apply sorting
            sort_field = f"-{params['sort_by']}" if params['sort_order'] == 'desc' else params['sort_by']
            query = query.order_by(sort_field)

            # Apply pagination
            start_index = (page - 1) * page_size
            databases = query[start_index:start_index + page_size]

            # Build response data - minimal fields for list view
            databases_data = [
                {
                    'breach_database_id': db.id,
                    'source_name': db.source_name,
                    'source_url': db.source_url,
                    'total_hashes': db.total_hashes
                }
                for db in databases
            ]

            # Calculate total pages
            total_pages = (total_count + page_size - 1) // page_size

            return {
                'data': databases_data,
                'pagination': {
                    'total': total_count,
                    'page': page,
                    'page_size': page_size,
                    'total_pages': total_pages
                },
                'sorting': {
                    'sort_by': params['sort_by'],
                    'sort_order': params['sort_order']
                }
            }

        except Exception as e:
            traceback.print_exc(e)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {'message': GenericConstants.ERROR_MESSAGE}
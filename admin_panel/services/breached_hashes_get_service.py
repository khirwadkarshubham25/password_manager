import sys
import traceback

from rest_framework import status

from admin_panel.models import BreachedPasswordHash
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class BreachedHashesGetService(AdminPanelServiceHelper):

    ALLOWED_SORT_FIELDS = ['occurrence_count', 'severity', 'created_at']

    SORT_FIELD_MAPPING = {
        'occurrence_count': 'occurrence_count',
        'severity': 'severity',
        'created_at': 'created_at'
    }

    VALID_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'page': data.get('page', '1').strip(),
            'page_size': data.get('page_size', '10').strip(),
            'sort_by': data.get('sort_by', 'occurrence_count').strip(),
            'sort_order': data.get('sort_order', 'desc').strip().lower(),
            'severity': data.get('severity', '').strip().upper(),
            'breach_database_id': data.get('breach_database_id', '').strip()
        }

    def _validate_severity(self, severity):
        if severity and severity not in self.VALID_SEVERITIES:
            return False, f"Invalid severity. Must be one of: {', '.join(self.VALID_SEVERITIES)}"
        return True, None

    def _validate_breach_database_id(self, breach_database_id):
        if breach_database_id:
            try:
                return True, int(breach_database_id), None
            except (ValueError, TypeError):
                return False, None, 'Invalid breach_database_id. Must be numeric'
        return True, None, None

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            page = int(params.get('page'))
            page_size = int(params.get('page_size'))
            sort_by = params.get('sort_by')
            sort_order = params.get('sort_order')

            is_valid, message = self.validate_pagination_params(page, page_size)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            is_valid, message = self.validate_sort_params(self.ALLOWED_SORT_FIELDS, sort_by, sort_order)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            is_valid, message = self._validate_severity(params['severity'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            is_valid, breach_database_id, error_msg = self._validate_breach_database_id(params['breach_database_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            query = BreachedPasswordHash.objects.select_related('breach_database').all()

            if params['severity']:
                query = query.filter(severity=params['severity'])

            if breach_database_id:
                query = query.filter(breach_database_id=breach_database_id)

            total_count = query.count()

            actual_sort_field = self.SORT_FIELD_MAPPING.get(sort_by, 'occurrence_count')
            sort_field = f'-{actual_sort_field}' if sort_order == 'desc' else actual_sort_field
            query = query.order_by(sort_field)

            start_index = (page - 1) * page_size
            hashes = query[start_index:start_index + page_size]

            hashes_data = [
                {
                    'breach_hash_id': hash_obj.id,
                    'password_hash': hash_obj.password_hash,
                    'hash_format': hash_obj.hash_format,
                    'occurrence_count': hash_obj.occurrence_count,
                    'severity': hash_obj.severity,
                    'breach_database_id': hash_obj.breach_database_id,
                    'breach_source_name': hash_obj.breach_database.source_name,
                    'created_at': hash_obj.created_at.isoformat()
                }
                for hash_obj in hashes
            ]

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
                    'sort_by': sort_by,
                    'sort_order': sort_order
                },
                'filters': {
                    'severity': params['severity'],
                    'breach_database_id': params['breach_database_id']
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
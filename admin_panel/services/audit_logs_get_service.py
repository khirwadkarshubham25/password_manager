import sys
import traceback

from rest_framework import status

from admin_panel.models import AuditLogs
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class AuditLogsGetService(AdminPanelServiceHelper):

    ALLOWED_SORT_FIELDS = ['action', 'resource_type', 'created_at']
    VALID_ACTIONS = ['create', 'update', 'delete']

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'page': data.get('page', '1').strip(),
            'page_size': data.get('page_size', '10').strip(),
            'sort_by': data.get('sort_by', 'created_at').strip(),
            'sort_order': data.get('sort_order', 'desc').strip().lower(),
            'action': data.get('action', '').strip().lower(),
            'resource_type': data.get('resource_type', '').strip().lower(),
            'user_id': data.get('user_id', '').strip()
        }

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

            if params['action'] and params['action'] not in self.VALID_ACTIONS:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': f"Invalid action. Must be one of: {', '.join(self.VALID_ACTIONS)}"}

            query = AuditLogs.objects.select_related('user').all()

            if params['action']:
                query = query.filter(action=params['action'])
            if params['resource_type']:
                query = query.filter(resource_type=params['resource_type'])
            if params['user_id']:
                try:
                    query = query.filter(user_id=int(params['user_id']))
                except (ValueError, TypeError):
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': 'Invalid user_id filter. Must be numeric'}

            total_count = query.count()

            sort_field = f'-{sort_by}' if sort_order == 'desc' else sort_by
            query = query.order_by(sort_field)

            start_index = (page - 1) * page_size
            logs = query[start_index:start_index + page_size]

            logs_data = [
                {
                    'audit_log_id': log.id,
                    'user_id': log.user.id if log.user else None,
                    'user_email': log.user.email if log.user else None,
                    'action': log.action,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'ip_address': log.ip_address,
                    'created_at': log.created_at.isoformat()
                }
                for log in logs
            ]

            total_pages = (total_count + page_size - 1) // page_size

            return {
                'data': logs_data,
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
                    'action': params['action'],
                    'resource_type': params['resource_type'],
                    'user_id': params['user_id']
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
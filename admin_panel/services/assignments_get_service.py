import sys
import traceback

from rest_framework import status

from admin_panel.models import PolicyAssignment
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class AssignmentsGetService(AdminPanelServiceHelper):

    ALLOWED_SORT_FIELDS = ['policy_name', 'first_name', 'last_name', 'created_at']

    SORT_FIELD_MAPPING = {
        'policy_name': 'policy__policy_name',
        'first_name': 'user__first_name',
        'last_name': 'user__last_name',
        'created_at': 'created_at'
    }

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'page': data.get('page', '1').strip(),
            'page_size': data.get('page_size', '10').strip(),
            'sort_by': data.get('sort_by', 'created_at').strip(),
            'sort_order': data.get('sort_order', 'desc').strip().lower()
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

            query = PolicyAssignment.objects.select_related(
                'policy',
                'user',
                'assigned_by'
            ).values(
                'id',
                'policy__id',
                'policy__policy_name',
                'user__id',
                'user__first_name',
                'user__last_name',
                'user__email',
                'assigned_by__id',
                'assigned_by__email',
                'created_at'
            )

            total_count = query.count()

            actual_sort_field = self.SORT_FIELD_MAPPING.get(sort_by, 'created_at')
            sort_field = f'-{actual_sort_field}' if sort_order == 'desc' else actual_sort_field
            query = query.order_by(sort_field)

            start_index = (page - 1) * page_size
            assignments = query[start_index:start_index + page_size]

            assignments_data = [
                {
                    'assignment_id': assignment['id'],
                    'policy_id': assignment['policy__id'],
                    'policy_name': assignment['policy__policy_name'],
                    'user_id': assignment['user__id'],
                    'first_name': assignment['user__first_name'],
                    'last_name': assignment['user__last_name'],
                    'email': assignment['user__email'],
                    'assigned_by_id': assignment['assigned_by__id'],
                    'assigned_by_email': assignment['assigned_by__email'],
                    'created_at': assignment['created_at'].isoformat() if assignment['created_at'] else None
                }
                for assignment in assignments
            ]

            total_pages = (total_count + page_size - 1) // page_size

            return {
                'data': assignments_data,
                'pagination': {
                    'total': total_count,
                    'page': page,
                    'page_size': page_size,
                    'total_pages': total_pages
                },
                'sorting': {
                    'sort_by': sort_by,
                    'sort_order': sort_order
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
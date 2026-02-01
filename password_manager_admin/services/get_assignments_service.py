import traceback

from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager.validators.page_validator import PageValidator
from password_manager.validators.sort_validator import SortValidator
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import PolicyAssignment


class GetAssignmentsService(PasswordAdminManagerServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        page = kwargs.get('data', {}).get('page', '1').strip()
        page_size = kwargs.get('data', {}).get('page_size', '10').strip()
        sort_by = kwargs.get('data', {}).get('sort_by', 'created_at').strip()
        sort_order = kwargs.get('data', {}).get('sort_order', 'desc').strip().lower()

        return {
            'page': page,
            'page_size': page_size,
            'sort_by': sort_by,
            'sort_order': sort_order
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, message = PageValidator().validate_pagination_params(
                params['page'], params['page_size']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            sort_field_mapping = {
                'policy_name': 'password_policy__policy_name',
                'first_name': 'users__first_name',
                'last_name': 'users__last_name',
                'created_at': 'created_at'
            }

            is_valid, message = SortValidator().validate_sort_params(
                ['policy_name', 'first_name', 'last_name', 'created_at'],
                params['sort_by'],
                params['sort_order']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Simplified query without annotate - directly use values()
            query = PolicyAssignment.objects.select_related(
                'password_policy',
                'user'
            ).values(
                'id',
                'password_policy__id',
                'password_policy__policy_name',
                'user__id',
                'user__first_name',
                'user__last_name',
                'created_at',
                'status'
            )

            total_count = query.count()

            actual_sort_field = sort_field_mapping.get(params['sort_by'], 'created_at')
            sort_field = f"-{actual_sort_field}" if params['sort_order'] == 'desc' else actual_sort_field
            query = query.order_by(sort_field)

            page = int(params['page'])
            page_size = int(params['page_size'])
            start_index = (page - 1) * page_size
            assignments = query[start_index:start_index + page_size]

            assignments_data = [
                {
                    'assignment_id': assignment['id'],
                    'policy_id': assignment['password_policy__id'],
                    'policy_name': assignment['password_policy__policy_name'],
                    'user_id': assignment['user__id'],
                    'first_name': assignment['user__first_name'],
                    'last_name': assignment['user__last_name'],
                    'created_at': assignment['created_at'].isoformat() if assignment['created_at'] else None,
                    'is_active': True if assignment['status'] == 1 else False
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
                    'sort_by': params['sort_by'],
                    'sort_order': params['sort_order']
                }
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
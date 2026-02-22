import sys
import traceback

from rest_framework import status

from admin_panel.models import PasswordPolicy
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class PoliciesGetService(AdminPanelServiceHelper):

    ALLOWED_SORT_FIELDS = ['policy_name', 'min_length', 'max_length', 'min_complexity_types', 'created_at']

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'page': data.get('page', '1').strip(),
            'page_size': data.get('page_size', '10').strip(),
            'sort_by': data.get('sort_by', 'created_at').strip(),
            'sort_order': data.get('sort_order', 'desc').strip().lower(),
            'is_active': data.get('is_active', '')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            page = int(params.get('page'))
            page_size = int(params.get('page_size'))
            sort_by = params.get('sort_by')
            sort_order = params.get('sort_order')
            is_active = params.get('is_active')

            is_valid, message = self.validate_pagination_params(page, page_size)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            is_valid, message = self.validate_sort_params(self.ALLOWED_SORT_FIELDS, sort_by, sort_order)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            query = PasswordPolicy.objects.all()

            if is_active:
                query = query.filter(status=1)

            total_count = query.count()

            sort_field = f'-{sort_by}' if sort_order == 'desc' else sort_by
            query = query.order_by(sort_field)

            start_index = (page - 1) * page_size
            end_index = start_index + page_size
            policies = query[start_index:end_index]

            policies_data = [
                {
                    'policy_id': policy.id,
                    'policy_name': policy.policy_name,
                    'description': policy.description,
                    'min_length': policy.min_length,
                    'max_length': policy.max_length,
                    'min_complexity_types': policy.min_complexity_types,
                    'min_entropy_score': policy.min_entropy_score,
                    'status': policy.status,
                    'created_at': policy.created_at.isoformat()
                }
                for policy in policies
            ]

            total_pages = (total_count + page_size - 1) // page_size

            return {
                'data': policies_data,
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
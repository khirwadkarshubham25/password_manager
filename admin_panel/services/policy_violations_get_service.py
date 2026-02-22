import sys
import traceback

from rest_framework import status

from admin_panel.models import PolicyViolation
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class PolicyViolationsGetService(AdminPanelServiceHelper):

    ALLOWED_SORT_FIELDS = ['violation_code', 'violation_name', 'severity', 'category', 'created_at']
    VALID_SEVERITIES    = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    VALID_CATEGORIES    = ['LENGTH', 'COMPLEXITY', 'PATTERNS', 'HISTORY', 'PERSONAL_INFO', 'BREACH']

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'page':       data.get('page', '1').strip(),
            'page_size':  data.get('page_size', '10').strip(),
            'sort_by':    data.get('sort_by', 'created_at').strip(),
            'sort_order': data.get('sort_order', 'desc').strip().lower(),
            'severity':   data.get('severity', '').strip().upper(),
            'category':   data.get('category', '').strip().upper(),
            'user_id':    data.get('user_id', '').strip()
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            page      = int(params['page'])
            page_size = int(params['page_size'])
            sort_by   = params['sort_by']
            sort_order = params['sort_order']

            is_valid, message = self.validate_pagination_params(page, page_size)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            is_valid, message = self.validate_sort_params(self.ALLOWED_SORT_FIELDS, sort_by, sort_order)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            if params['severity'] and params['severity'] not in self.VALID_SEVERITIES:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': f"Invalid severity. Must be one of: {', '.join(self.VALID_SEVERITIES)}"}

            if params['category'] and params['category'] not in self.VALID_CATEGORIES:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': f"Invalid category. Must be one of: {', '.join(self.VALID_CATEGORIES)}"}

            # Only return user violation records (not seed/reference rows)
            query = PolicyViolation.objects.select_related('user').filter(
                user__isnull=False
            )

            if params['severity']:
                query = query.filter(severity=params['severity'])

            if params['category']:
                query = query.filter(category=params['category'])

            if params['user_id']:
                query = query.filter(user_id=params['user_id'])

            total_count = query.count()
            sort_field  = f'-{sort_by}' if sort_order == 'desc' else sort_by
            query       = query.order_by(sort_field)

            start       = (page - 1) * page_size
            violations  = query[start:start + page_size]

            violations_data = [
                {
                    'violation_id': v.id,
                    'violation_code': v.violation_code,
                    'violation_name': v.violation_name,
                    'severity': v.severity,
                    'category': v.category,
                    'user_id': v.user.id,
                    'first_name': v.user.first_name,
                    'last_name': v.user.last_name,
                    'email': v.user.email,
                    'created_at': v.created_at.isoformat()
                }
                for v in violations
            ]

            total_pages = (total_count + page_size - 1) // page_size

            return {
                'data': violations_data,
                'pagination': {
                    'total':       total_count,
                    'page':        page,
                    'page_size':   page_size,
                    'total_pages': total_pages
                },
                'sorting': {
                    'sort_by':    sort_by,
                    'sort_order': sort_order
                },
                'filters': {
                    'severity': params['severity'],
                    'category': params['category'],
                    'user_id':  params['user_id']
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
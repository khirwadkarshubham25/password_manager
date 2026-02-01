from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager.validators.page_validator import PageValidator
from password_manager.validators.sort_validator import SortValidator
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import Users


class GetUsersService(PasswordAdminManagerServiceHelper):

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

            page = int(params.get('page'))
            page_size = int(params.get('page_size'))
            sort_by = params.get('sort_by')
            sort_order = params.get('sort_order')

            is_valid, message = PageValidator().validate_pagination_params(page, page_size)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            is_valid, message = SortValidator().validate_sort_params(['username', 'email', 'first_name', 'last_name', 'created_at'], sort_by, sort_order)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            query = Users.objects.all()
            total_count = query.count()

            if sort_order == 'desc':
                sort_field = f'-{sort_by}'
            else:
                sort_field = sort_by

            query = query.order_by(sort_field)

            # Calculate pagination
            start_index = (page - 1) * page_size
            end_index = start_index + page_size

            # Apply pagination
            users = query[start_index:end_index]

            # Build response data
            users_data = []
            for user in users:
                users_data.append({
                    'user_id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'created_at': user.created_at.isoformat(),
                })

            total_pages = (total_count + page_size - 1) // page_size

            return {
                'data': users_data,
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

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE
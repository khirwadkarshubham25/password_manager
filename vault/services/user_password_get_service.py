import sys
import traceback

from rest_framework import status

from accounts.models import Users
from vault.models import UserPasswords
from vault.services.service_helper.vault_service_helper import VaultServiceHelper
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.crypto_service import CryptoService


class UserPasswordsGetService(VaultServiceHelper):

    ALLOWED_SORT_FIELDS = ['platform', 'email', 'url', 'created_at', 'updated_at']

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'user_id':    data.get('user_id', ''),
            'page':       data.get('page', '1'),
            'page_size':  data.get('page_size', '10'),
            'sort_by':    data.get('sort_by', 'created_at'),
            'sort_order': data.get('sort_order', 'desc'),
            'search':     data.get('search', '').strip()
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, error = self.is_valid_parameters(params, required_fields=['user_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return error

            try:
                page      = int(params['page'])
                page_size = int(params['page_size'])
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Page and page_size must be valid integers.'}

            is_valid, message = self.validate_pagination_params(page, page_size)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            is_valid, message = self.validate_sort_params(
                self.ALLOWED_SORT_FIELDS,
                params['sort_by'],
                params['sort_order']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            try:
                user = Users.objects.get(id=params['user_id'])
            except Users.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.USER_NOT_FOUND}

            queryset = UserPasswords.objects.filter(user_id=params['user_id'])

            if params['search']:
                queryset = queryset.filter(platform__icontains=params['search']) | \
                           queryset.filter(email__icontains=params['search']) | \
                           queryset.filter(url__icontains=params['search'])

            sort_field = params['sort_by'] if params['sort_order'] == 'asc' else f"-{params['sort_by']}"
            queryset = queryset.order_by(sort_field)

            total_count = queryset.count()
            total_pages = (total_count + page_size - 1) // page_size

            offset = (page - 1) * page_size
            entries = queryset[offset: offset + page_size]

            passwords_data = []
            for entry in entries:
                try:
                    decrypted_password = CryptoService.decrypt_password(
                        entry.password,
                        user.password
                    )
                except Exception:
                    decrypted_password = None

                passwords_data.append({
                    'user_password_id': entry.id,
                    'platform': entry.platform,
                    'url': entry.url,
                    'email': entry.email,
                    'password': decrypted_password,
                    'created_at': entry.created_at.isoformat(),
                    'updated_at': entry.updated_at.isoformat()
                })

            return {
                'data': passwords_data,
                'pagination': {
                    'total': total_count,
                    'page': page,
                    'page_size': page_size,
                    'total_pages': total_pages
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE